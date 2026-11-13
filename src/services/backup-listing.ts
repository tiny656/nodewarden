import { SaxesParser } from 'saxes';

export const REMOTE_LISTING_LIMITS = {
  responseBytes: 2 * 1024 * 1024,
  depth: 32,
  elements: 50_000,
  fieldCharacters: 16 * 1024,
  entries: 10_000,
  pages: 10,
  timeoutMs: 30_000,
} as const;

export interface ListingElement {
  name: string;
  namespace: string;
  text: string;
  children: ListingElement[];
}

/** One deadline includes fetching headers, streaming bodies, and all S3 pages. */
export async function withListingDeadline<T>(
  run: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number = REMOTE_LISTING_LIMITS.timeoutMs
): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      const error = new Error('Remote backup listing timed out');
      controller.abort(error);
      reject(error);
    }, timeoutMs);
  });
  try {
    return await Promise.race([run(controller.signal), timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Parse once, with bounded bytes/nodes/depth and no DTD or external entities. */
export async function readListingXml(response: Response, signal: AbortSignal): Promise<ListingElement> {
  const declaredLength = Number(response.headers.get('Content-Length'));
  if (declaredLength > REMOTE_LISTING_LIMITS.responseBytes) {
    void response.body?.cancel().catch(() => undefined);
    throw new Error('Remote backup listing is too large');
  }
  if (!response.body) throw new Error('Remote backup listing is empty');
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener('abort', cancel, { once: true });
  const throwIfAborted = () => {
    if (signal.aborted) throw new Error('Remote backup listing timed out');
  };
  const parser = new SaxesParser({ xmlns: true });
  const stack: Array<{ element: ListingElement; chunks: string[]; textLength: number }> = [];
  let root: ListingElement | null = null;
  let elements = 0;
  let attributes = 0;
  let totalBytes = 0;

  parser.on('error', () => { throw new Error('Remote backup listing contains malformed XML'); });
  parser.on('doctype', () => { throw new Error('Remote backup listing must not contain a DTD'); });
  parser.on('xmldecl', (declaration) => {
    if (declaration.encoding && declaration.encoding.toUpperCase() !== 'UTF-8') {
      throw new Error('Remote backup listing must use UTF-8');
    }
  });
  parser.on('opentagstart', (tag) => {
    if (++elements > REMOTE_LISTING_LIMITS.elements) throw new Error('Remote backup listing has too many XML elements');
    if (stack.length >= REMOTE_LISTING_LIMITS.depth) throw new Error('Remote backup listing XML is too deeply nested');
    if (tag.name.length > 256) throw new Error('Remote backup listing XML name is too long');
    attributes = 0;
  });
  parser.on('attribute', (attribute) => {
    if (++attributes > 32 || attribute.name.length > 256 || attribute.value.length > REMOTE_LISTING_LIMITS.fieldCharacters) {
      throw new Error('Remote backup listing XML attributes exceed limits');
    }
  });
  parser.on('opentag', (tag) => {
    const element: ListingElement = { name: tag.local, namespace: tag.uri, text: '', children: [] };
    if (stack.length) stack[stack.length - 1].element.children.push(element);
    else root = element;
    stack.push({ element, chunks: [], textLength: 0 });
  });
  const addText = (text: string) => {
    const current = stack[stack.length - 1];
    if (!current) return;
    current.textLength += text.length;
    // Container whitespace is bounded by the response budget. Leaf fields have
    // their own tighter bound, checked when the element is complete.
    current.chunks.push(text);
  };
  parser.on('text', addText);
  parser.on('cdata', addText);
  parser.on('closetag', () => {
    const current = stack.pop()!;
    if (!current.element.children.length && current.textLength > REMOTE_LISTING_LIMITS.fieldCharacters) {
      throw new Error('Remote backup listing XML field is too long');
    }
    current.element.text = current.chunks.join('');
  });

  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
  try {
    throwIfAborted();
    while (true) {
      const { done, value } = await reader.read();
      throwIfAborted();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > REMOTE_LISTING_LIMITS.responseBytes) throw new Error('Remote backup listing is too large');
      parser.write(decoder.decode(value, { stream: true }));
    }
    parser.write(decoder.decode()).close();
    if (!root) throw new Error('Remote backup listing is empty');
    return root;
  } catch (error) {
    cancel();
    throw error;
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

export function listingChildren(element: ListingElement, name: string): ListingElement[] {
  return element.children.filter((child) => child.name === name && child.namespace === element.namespace);
}

export function listingChild(element: ListingElement, name: string): ListingElement | undefined {
  return element.children.find((child) => child.name === name && child.namespace === element.namespace);
}

export function listingText(element: ListingElement, name: string): string {
  const child = listingChild(element, name);
  if (!child) return '';
  if (child.children.length) throw new Error('Remote backup listing contains an invalid text field');
  return child.text.trim();
}

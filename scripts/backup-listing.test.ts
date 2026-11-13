import assert from 'node:assert/strict';
import test from 'node:test';
import { createBackupDestinationRecord } from '../shared/backup-schema';
import { listRemoteBackupEntries, pruneRemoteBackupArchives } from '../src/services/backup-uploader';
import { listingChild, listingText, readListingXml, REMOTE_LISTING_LIMITS, withListingDeadline } from '../src/services/backup-listing';

const encoder = new TextEncoder();
const signal = () => new AbortController().signal;

function webdav() {
  return {
    ...createBackupDestinationRecord('webdav', 1),
    destination: { baseUrl: 'https://storage.example.test/dav', username: 'test', password: 'synthetic-password', remotePath: 'backups' },
  };
}

function s3() {
  return {
    ...createBackupDestinationRecord('s3', 1),
    destination: { endpoint: 'https://storage.example.test', bucket: 'vault-backups', addressingStyle: 'path-style' as const,
      region: 'auto', accessKeyId: 'test', secretAccessKey: 'synthetic-secret', rootPath: 'backups' },
  };
}

function s3Page(body: string) {
  return `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">${body}</ListBucketResult>`;
}

test('XML supports namespaces, entities, CDATA and split UTF-8 characters', async () => {
  const xml = encoder.encode('<?xml version="1.0" encoding="UTF-8"?><x:root xmlns:x="DAV:"><x:name>A&amp;B&#39;文<![CDATA[<tail>]]></x:name></x:root>');
  let offset = 0;
  const response = new Response(new ReadableStream({
    pull(controller) {
      if (offset >= xml.length) controller.close();
      else controller.enqueue(xml.slice(offset, ++offset));
    },
  }));
  const root = await readListingXml(response, signal());
  assert.equal(root.namespace, 'DAV:');
  assert.equal(listingText(root, 'name'), "A&B'文<tail>");
});

test('WebDAV lists direct children and ignores failed properties and foreign namespaces', async (ctx) => {
  ctx.mock.method(globalThis, 'fetch', async (_input: unknown, init: RequestInit) => {
    assert.equal(init.method, 'PROPFIND');
    assert.ok(init.signal);
    assert.equal(init.redirect, 'error');
    return new Response(`<d:multistatus xmlns:d="DAV:" xmlns:other="urn:other">
      <d:response><d:href>/dav/backups/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
      <d:response><d:href>/dav/backups/attachments/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
      <d:response><d:href>/dav/backups/A%26B.zip</d:href>
        <d:propstat><d:prop><d:getcontentlength>999</d:getcontentlength></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
        <d:propstat><d:prop><d:resourcetype/><other:getcontentlength>777</other:getcontentlength><d:getcontentlength>42</d:getcontentlength><d:getlastmodified>Fri, 13 Nov 2026 00:00:00 GMT</d:getlastmodified></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
      </d:response>
      <d:response><d:href>/dav/backups/attachments/nested.bin</d:href></d:response>
      <d:response><d:href>/dav/outside.zip</d:href></d:response>
      <other:response><other:href>/dav/backups/untrusted.zip</other:href></other:response>
    </d:multistatus>`, { status: 207 });
  });
  const listing = await listRemoteBackupEntries(webdav(), '');
  assert.deepEqual(listing.items.map((item) => item.path), ['attachments', 'A&B.zip']);
  assert.equal(listing.items[0].isDirectory, true);
  assert.equal(listing.items[1].size, 42);
  assert.equal(listing.items[1].modifiedAt, '2026-11-13T00:00:00.000Z');
});

test('S3 pagination decodes entities and keeps root and direct-child filtering', async (ctx) => {
  let requests = 0;
  let sharedSignal: AbortSignal | undefined;
  ctx.mock.method(globalThis, 'fetch', async (input: URL, init: RequestInit) => {
    const url = new URL(input);
    assert.equal(url.searchParams.get('max-keys'), '1000');
    assert.equal(init.redirect, 'error');
    if (sharedSignal) assert.equal(init.signal, sharedSignal);
    sharedSignal = init.signal!;
    if (++requests === 1) {
      return new Response(s3Page('<CommonPrefixes><Prefix>backups/attachments/</Prefix></CommonPrefixes><Contents><Key>backups/A&amp;B.zip</Key><Size>12</Size></Contents><IsTruncated>true</IsTruncated><NextContinuationToken>next&amp;token</NextContinuationToken>'));
    }
    assert.equal(url.searchParams.get('continuation-token'), 'next&token');
    return new Response(s3Page('<Contents><Key>backups/second.zip</Key><Size>34</Size></Contents><Contents><Key>outside.zip</Key></Contents><Contents><Key>backups/nested/file.zip</Key></Contents><IsTruncated>false</IsTruncated>'));
  });
  const listing = await listRemoteBackupEntries(s3(), '');
  assert.equal(requests, 2);
  assert.deepEqual(listing.items.map((item) => item.path), ['attachments', 'A&B.zip', 'second.zip']);
});

test('malformed XML, repeated delimiters, DTDs and entity expansion are rejected', async () => {
  for (const xml of [
    '<'.repeat(100_000), '<root><a></root>', '<root>&unknown;</root>',
    '<!DOCTYPE root SYSTEM "https://example.test/secret"><root/>',
    '<!DOCTYPE root [<!ENTITY x "expanded">]><root>&x;</root>',
    '<root/><another/>',
  ]) await assert.rejects(() => readListingXml(new Response(xml), signal()), /malformed XML|DTD/);
});

test('response, field, node, attribute and depth limits fail closed', async () => {
  await assert.rejects(() => readListingXml(new Response('<root/>', {
    headers: { 'Content-Length': String(REMOTE_LISTING_LIMITS.responseBytes + 1) },
  }), signal()), /too large/);
  await assert.rejects(() => readListingXml(new Response(' '.repeat(REMOTE_LISTING_LIMITS.responseBytes + 1), {
    headers: { 'Content-Length': '1' },
  }), signal()), /too large/);
  await assert.rejects(() => readListingXml(new Response('<root><value>' + 'x'.repeat(REMOTE_LISTING_LIMITS.fieldCharacters + 1) + '</value></root>'), signal()), /field is too long/);
  await assert.rejects(() => readListingXml(new Response('<root>' + '<a/>'.repeat(REMOTE_LISTING_LIMITS.elements) + '</root>'), signal()), /too many XML elements/);
  await assert.rejects(() => readListingXml(new Response('<a>'.repeat(REMOTE_LISTING_LIMITS.depth + 1) + '</a>'.repeat(REMOTE_LISTING_LIMITS.depth + 1)), signal()), /deeply nested/);
  await assert.rejects(() => readListingXml(new Response('<a ' + Array.from({ length: 33 }, (_, i) => `a${i}="value"`).join(' ') + '/>'), signal()), /attributes exceed/);
});

test('parsing errors cancel the response stream and release its lock', async () => {
  let canceled = false;
  const body = new ReadableStream<Uint8Array>({
    start(controller) { controller.enqueue(encoder.encode('<<')); },
    cancel() { canceled = true; },
  });
  await assert.rejects(() => readListingXml(new Response(body), signal()), /malformed XML/);
  assert.equal(canceled, true);
  assert.equal(body.locked, false);
});

test('deadline covers stalled headers and response bodies', async () => {
  let headerSignal: AbortSignal | undefined;
  await assert.rejects(() => withListingDeadline(async (signal) => {
    headerSignal = signal;
    return new Promise<never>(() => {});
  }, 15), /timed out/);
  assert.equal(headerSignal?.aborted, true);
  let canceled = false;
  const body = new ReadableStream<Uint8Array>({ cancel() { canceled = true; } });
  await assert.rejects(() => withListingDeadline((signal) => readListingXml(new Response(body), signal), 15), /timed out/);
  assert.equal(canceled, true);
});

test('S3 refuses repeated continuation tokens and unbounded pages', async (ctx) => {
  let requests = 0;
  let repeated = true;
  ctx.mock.method(globalThis, 'fetch', async () => {
    requests += 1;
    return new Response(s3Page(`<IsTruncated>true</IsTruncated><NextContinuationToken>${repeated ? 'same' : requests}</NextContinuationToken>`));
  });
  await assert.rejects(() => listRemoteBackupEntries(s3(), ''), /repeated a continuation token/);
  assert.equal(requests, 2);
  requests = 0;
  repeated = false;
  await assert.rejects(() => listRemoteBackupEntries(s3(), ''), /too many pages/);
  assert.equal(requests, REMOTE_LISTING_LIMITS.pages);
});

test('S3 entry limits and incomplete pages never return a partial pruning list', async (ctx) => {
  const firstPage = s3Page(['old', 'middle', 'new'].map((name) =>
    `<Contents><Key>backups/${name}.zip</Key></Contents>`
  ).join('') + '<IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken>');
  let finalPage = '';
  let deletes = 0;
  ctx.mock.method(globalThis, 'fetch', async (input: URL, init: RequestInit) => {
    if (init.method === 'DELETE') {
      deletes += 1;
      return new Response(null, { status: 204 });
    }
    return new Response(new URL(input).searchParams.has('continuation-token') ? finalPage : firstPage);
  });
  for (const [body, message] of [
    ['<IsTruncated>true</IsTruncated>', /truncated without/],
    ['', /invalid pagination status/],
    ['<IsTruncated>unknown</IsTruncated>', /invalid pagination status/],
    ['<IsTruncated>false</IsTruncated><NextContinuationToken>extra</NextContinuationToken>', /unexpected continuation token/],
    ['<Contents>', /malformed XML/],
  ] as const) {
    finalPage = s3Page(body);
    await assert.rejects(() => pruneRemoteBackupArchives(s3(), 1), message);
  }
  finalPage = s3Page('<Contents><Key>backups/file.zip</Key></Contents>'.repeat(REMOTE_LISTING_LIMITS.entries + 1));
  await assert.rejects(() => pruneRemoteBackupArchives(s3(), 1), /too many entries/);
  assert.equal(deletes, 0);
});

test('XML text access cannot flatten injected nested elements', async () => {
  const root = await readListingXml(new Response('<root><name>A<other>B</other></name></root>'), signal());
  assert.ok(listingChild(root, 'name'));
  assert.throws(() => listingText(root, 'name'), /invalid text field/);
});

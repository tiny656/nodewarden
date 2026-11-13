import { trimCharacter, trimTrailingCharacter } from '../../shared/trim-character';
import {
  BackupDestinationRecord,
  BackupDestinationType,
  S3BackupDestination,
  WebDavBackupDestination,
  normalizeBackupEndpointUrl,
} from './backup-config';
import {
  listingChild,
  listingChildren,
  listingText,
  readListingXml,
  REMOTE_LISTING_LIMITS,
  withListingDeadline,
} from './backup-listing';

export interface BackupUploadResult {
  provider: BackupDestinationType;
  remotePath: string;
}

export interface RemoteBackupItem {
  path: string;
  name: string;
  isDirectory: boolean;
  size: number | null;
  modifiedAt: string | null;
}

export interface RemoteBackupListResult {
  provider: BackupDestinationType;
  currentPath: string;
  parentPath: string | null;
  items: RemoteBackupItem[];
}

export interface RemoteBackupFile {
  provider: BackupDestinationType;
  remotePath: string;
  fileName: string;
  contentType: string;
  bytes: Uint8Array;
}

export interface RemoteBackupFileStat {
  provider: BackupDestinationType;
  remotePath: string;
  size: number | null;
  modifiedAt: string | null;
}

export interface RemoteBackupFilePutOptions {
  contentType?: string;
}

function isBackupArchiveName(name: string): boolean {
  return /\.zip$/i.test(String(name || '').trim());
}

function encodePathSegments(path: string): string {
  return path
    .split('/')
    .filter(Boolean)
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

function trimSlashes(value: string): string {
  return trimCharacter(String(value || ''), '/');
}

function buildJoinedPath(...segments: string[]): string {
  return segments.map(trimSlashes).filter(Boolean).join('/');
}

function normalizeRelativePath(path: string): string {
  const normalized = trimSlashes(path).replace(/\\/g, '/');
  if (!normalized) return '';
  const parts = normalized.split('/').filter(Boolean);
  if (parts.some((part) => part === '.' || part === '..')) {
    throw new Error('Invalid remote backup path');
  }
  return parts.join('/');
}

function basename(path: string): string {
  const normalized = trimSlashes(path);
  if (!normalized) return '';
  const parts = normalized.split('/').filter(Boolean);
  return parts[parts.length - 1] || '';
}

function parentPath(path: string): string | null {
  const normalized = normalizeRelativePath(path);
  if (!normalized) return null;
  const parts = normalized.split('/');
  parts.pop();
  return parts.length ? parts.join('/') : '';
}

function sortRemoteItems(items: RemoteBackupItem[]): RemoteBackupItem[] {
  return items.slice().sort((a, b) => {
    const aIsAttachmentsDir = a.isDirectory && a.name === 'attachments';
    const bIsAttachmentsDir = b.isDirectory && b.name === 'attachments';
    if (aIsAttachmentsDir !== bIsAttachmentsDir) return aIsAttachmentsDir ? -1 : 1;
    if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
    return a.name.localeCompare(b.name, 'en');
  });
}

function parseHttpDate(value: string): string | null {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

async function sha256Hex(value: Uint8Array | string): Promise<string> {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256Raw(keyBytes: Uint8Array, message: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return new Uint8Array(signature);
}

function toBasicAuthHeader(username: string, password: string): string {
  const token = btoa(`${username}:${password}`);
  return `Basic ${token}`;
}

function buildCanonicalQueryString(url: URL): string {
  const params = Array.from(url.searchParams.entries()).sort(([aKey, aValue], [bKey, bValue]) => {
    if (aKey === bKey) return aValue.localeCompare(bValue);
    return aKey.localeCompare(bKey);
  });
  return params
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
}

async function buildAwsV4Authorization(
  method: string,
  url: URL,
  headers: Record<string, string>,
  payloadHashHex: string,
  accessKeyId: string,
  secretAccessKey: string,
  region: string
): Promise<string> {
  const amzDate = headers['x-amz-date'];
  const shortDate = amzDate.slice(0, 8);
  const headerEntries = Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value] as const).sort(([a], [b]) => a.localeCompare(b));
  const canonicalHeaders = headerEntries
    .map(([name, value]) => `${name}:${String(value).trim().replace(/\s+/g, ' ')}`)
    .join('\n');
  const signedHeaders = headerEntries.map(([name]) => name).join(';');
  const canonicalRequest = [
    method.toUpperCase(),
    url.pathname || '/',
    buildCanonicalQueryString(url),
    `${canonicalHeaders}\n`,
    signedHeaders,
    payloadHashHex,
  ].join('\n');
  const credentialScope = `${shortDate}/${region}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join('\n');

  const kDate = await hmacSha256Raw(new TextEncoder().encode(`AWS4${secretAccessKey}`), shortDate);
  const kRegion = await hmacSha256Raw(kDate, region);
  const kService = await hmacSha256Raw(kRegion, 's3');
  const kSigning = await hmacSha256Raw(kService, 'aws4_request');
  const signatureBytes = await hmacSha256Raw(kSigning, stringToSign);
  const signature = Array.from(signatureBytes).map((byte) => byte.toString(16).padStart(2, '0')).join('');

  return `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

function ensureDestinationConfigReady(destination: BackupDestinationRecord): void {
  if (destination.type === 'webdav') {
    const config = destination.destination as WebDavBackupDestination;
    if (!String(config.baseUrl || '').trim()) throw new Error('WebDAV server URL is required');
    normalizeBackupEndpointUrl(String(config.baseUrl || '').trim(), 'WebDAV server URL');
    if (!String(config.username || '').trim()) throw new Error('WebDAV username is required');
    if (!String(config.password || '')) throw new Error('WebDAV password is required');
    return;
  }
  if (destination.type === 's3') {
    const config = destination.destination as S3BackupDestination;
    if (!String(config.endpoint || '').trim()) throw new Error('S3 endpoint is required');
    normalizeBackupEndpointUrl(String(config.endpoint || '').trim(), 'S3 endpoint');
    if (!String(config.bucket || '').trim()) throw new Error('S3 bucket is required');
    if (!String(config.accessKeyId || '').trim()) throw new Error('S3 access key is required');
    if (!String(config.secretAccessKey || '')) throw new Error('S3 secret key is required');
  }
}

function buildWebDavUrl(baseUrl: string, relativePath: string): string {
  const trimmedBase = trimTrailingCharacter(baseUrl, '/');
  const normalized = normalizeRelativePath(relativePath);
  return normalized ? `${trimmedBase}/${encodePathSegments(normalized)}` : trimmedBase;
}

function webDavFullPath(config: WebDavBackupDestination, relativePath: string): string {
  return buildJoinedPath(config.remotePath, normalizeRelativePath(relativePath));
}

async function ensureWebDavDirectory(baseUrl: string, directoryPath: string, authHeader: string): Promise<void> {
  const segments = trimSlashes(directoryPath).split('/').filter(Boolean);
  let current = '';
  for (const segment of segments) {
    current = buildJoinedPath(current, segment);
    const url = buildWebDavUrl(baseUrl, current);
    const response = await fetch(url, {
      method: 'MKCOL',
      headers: {
        Authorization: authHeader,
      },
    });
    if ([200, 201, 204, 405].includes(response.status)) continue;
    throw new Error(`WebDAV directory creation failed: ${response.status}`);
  }
}

async function ensureWebDavDirectoryCached(
  baseUrl: string,
  directoryPath: string,
  authHeader: string,
  ensuredDirectories: Set<string>
): Promise<void> {
  const segments = trimSlashes(directoryPath).split('/').filter(Boolean);
  let current = '';
  for (const segment of segments) {
    current = buildJoinedPath(current, segment);
    if (ensuredDirectories.has(current)) continue;
    const url = buildWebDavUrl(baseUrl, current);
    const response = await fetch(url, {
      method: 'MKCOL',
      headers: {
        Authorization: authHeader,
      },
    });
    if ([200, 201, 204, 405].includes(response.status)) {
      ensuredDirectories.add(current);
      continue;
    }
    throw new Error(`WebDAV directory creation failed: ${response.status}`);
  }
}

async function putToWebDav(
  config: WebDavBackupDestination,
  relativePath: string,
  bytes: Uint8Array,
  options: RemoteBackupFilePutOptions = {},
  ensuredDirectories?: Set<string>
): Promise<void> {
  const authHeader = toBasicAuthHeader(config.username, config.password);
  const remoteFilePath = buildJoinedPath(config.remotePath, relativePath);
  const remoteDir = parentPath(remoteFilePath);

  if (remoteDir) {
    if (ensuredDirectories) {
      await ensureWebDavDirectoryCached(config.baseUrl, remoteDir, authHeader, ensuredDirectories);
    } else {
      await ensureWebDavDirectory(config.baseUrl, remoteDir, authHeader);
    }
  }

  const response = await fetch(buildWebDavUrl(config.baseUrl, remoteFilePath), {
    method: 'PUT',
    headers: {
      Authorization: authHeader,
      'Content-Type': options.contentType || 'application/octet-stream',
      'Content-Length': String(bytes.byteLength),
    },
    body: bytes,
  });

  if (!response.ok) {
    throw new Error(`WebDAV upload failed: ${response.status}`);
  }
}

async function uploadToWebDav(config: WebDavBackupDestination, archive: Uint8Array, fileName: string): Promise<BackupUploadResult> {
  await putToWebDav(config, fileName, archive, { contentType: 'application/zip' });
  return {
    provider: 'webdav',
    remotePath: buildJoinedPath(config.remotePath, fileName),
  };
}

function parseWebDavResponsePath(baseUrl: string, href: string): string {
  const base = new URL(baseUrl);
  const target = new URL(href, base);
  const basePath = trimSlashes(decodeURIComponent(base.pathname));
  const entryPath = trimSlashes(decodeURIComponent(target.pathname));
  if (!basePath) return entryPath;
  if (entryPath === basePath) return '';
  return entryPath.startsWith(`${basePath}/`) ? entryPath.slice(basePath.length + 1) : entryPath;
}

async function listWebDavEntries(
  config: WebDavBackupDestination,
  relativePath: string,
  signal: AbortSignal
): Promise<RemoteBackupListResult> {
  const currentPath = normalizeRelativePath(relativePath);
  const targetFullPath = webDavFullPath(config, currentPath);
  const authHeader = toBasicAuthHeader(config.username, config.password);
  const response = await fetch(buildWebDavUrl(config.baseUrl, targetFullPath), {
    method: 'PROPFIND',
    headers: {
      Authorization: authHeader,
      Depth: '1',
      'Content-Type': 'application/xml; charset=utf-8',
    },
    body: `<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><resourcetype/><getcontentlength/><getlastmodified/></prop></propfind>`,
    signal,
    redirect: 'error',
  });
  if (response.status === 404) {
    void response.body?.cancel().catch(() => undefined);
    return {
      provider: 'webdav',
      currentPath,
      parentPath: parentPath(currentPath),
      items: [],
    };
  }
  if (!response.ok) {
    void response.body?.cancel().catch(() => undefined);
    throw new Error(`WebDAV listing failed: ${response.status}`);
  }

  const root = await readListingXml(response, signal);
  if (root.name !== 'multistatus' || !['DAV:', ''].includes(root.namespace)) {
    throw new Error('Remote backup listing is not a WebDAV multistatus response');
  }
  const rootFullPath = trimSlashes(config.remotePath);
  const items: RemoteBackupItem[] = [];
  const responses = listingChildren(root, 'response');
  if (responses.length > REMOTE_LISTING_LIMITS.entries) throw new Error('Remote backup listing has too many entries');
  for (const block of responses) {
    const href = listingText(block, 'href');
    if (!href) continue;
    const fullPath = trimSlashes(parseWebDavResponsePath(config.baseUrl, href));
    if (!fullPath) continue;
    if (fullPath === targetFullPath) continue;
    if (rootFullPath && !(fullPath === rootFullPath || fullPath.startsWith(`${rootFullPath}/`))) continue;
    const relative = rootFullPath
      ? fullPath === rootFullPath
        ? ''
        : fullPath.slice(rootFullPath.length + 1)
      : fullPath;
    if (!relative) continue;
    const directParent = parentPath(relative);
    if ((directParent || '') !== currentPath) continue;

    // Failed propstat blocks must not override successful property values.
    const properties = listingChildren(block, 'propstat')
      .filter((entry) => /^HTTP\/\S+ 2\d\d(?:\s|$)/.test(listingText(entry, 'status')))
      .flatMap((entry) => listingChildren(entry, 'prop'));
    if (!properties.length) continue;
    const isDirectory = properties.some((prop) => {
      const resourceType = listingChild(prop, 'resourcetype');
      return resourceType && listingChild(resourceType, 'collection');
    });
    const sizeRaw = properties.map((prop) => listingText(prop, 'getcontentlength')).find(Boolean) || '';
    const modifiedAtRaw = properties.map((prop) => listingText(prop, 'getlastmodified')).find(Boolean) || '';
    items.push({
      path: relative,
      name: basename(relative) || relative,
      isDirectory,
      size: !isDirectory && sizeRaw && Number.isFinite(Number(sizeRaw)) ? Number(sizeRaw) : null,
      modifiedAt: modifiedAtRaw ? parseHttpDate(modifiedAtRaw) : null,
    });
  }

  return {
    provider: 'webdav',
    currentPath,
    parentPath: parentPath(currentPath),
    items: sortRemoteItems(items),
  };
}

async function downloadFromWebDav(config: WebDavBackupDestination, relativePath: string): Promise<RemoteBackupFile> {
  const normalized = normalizeRelativePath(relativePath);
  if (!normalized || normalized.endsWith('/')) {
    throw new Error('Please select a backup file');
  }
  const authHeader = toBasicAuthHeader(config.username, config.password);
  const remotePath = webDavFullPath(config, normalized);
  const response = await fetch(buildWebDavUrl(config.baseUrl, remotePath), {
    method: 'GET',
    headers: {
      Authorization: authHeader,
    },
  });
  if (!response.ok) {
    throw new Error(`WebDAV download failed: ${response.status}`);
  }
  return {
    provider: 'webdav',
    remotePath: normalized,
    fileName: basename(normalized) || 'backup.zip',
    contentType: String(response.headers.get('Content-Type') || 'application/zip').trim() || 'application/zip',
    bytes: new Uint8Array(await response.arrayBuffer()),
  };
}

async function deleteFromWebDav(config: WebDavBackupDestination, relativePath: string): Promise<void> {
  const authHeader = toBasicAuthHeader(config.username, config.password);
  const remotePath = webDavFullPath(config, relativePath);
  const response = await fetch(buildWebDavUrl(config.baseUrl, remotePath), {
    method: 'DELETE',
    headers: {
      Authorization: authHeader,
    },
  });
  if (!response.ok && response.status !== 404) {
    throw new Error(`WebDAV delete failed: ${response.status}`);
  }
}

async function existsInWebDav(config: WebDavBackupDestination, relativePath: string): Promise<boolean> {
  return (await statWebDavFile(config, relativePath)) !== null;
}

async function statWebDavFile(config: WebDavBackupDestination, relativePath: string): Promise<RemoteBackupFileStat | null> {
  const authHeader = toBasicAuthHeader(config.username, config.password);
  const remotePath = webDavFullPath(config, relativePath);
  const response = await fetch(buildWebDavUrl(config.baseUrl, remotePath), {
    method: 'HEAD',
    headers: {
      Authorization: authHeader,
    },
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`WebDAV existence check failed: ${response.status}`);
  }
  const size = Number(response.headers.get('Content-Length') || '');
  return {
    provider: 'webdav',
    remotePath: normalizeRelativePath(relativePath),
    size: Number.isFinite(size) ? size : null,
    modifiedAt: parseHttpDate(response.headers.get('Last-Modified') || ''),
  };
}

function isBucketHostedS3Endpoint(endpoint: URL, bucket: string): boolean {
  const hostname = endpoint.hostname.toLowerCase();
  const bucketName = bucket.trim().toLowerCase();
  return !!bucketName && (hostname === bucketName || hostname.startsWith(`${bucketName}.`));
}

function s3BucketBaseUrl(config: S3BackupDestination): URL {
  const endpoint = new URL(trimTrailingCharacter(config.endpoint, '/'));
  const bucket = config.bucket.trim();

  if (config.addressingStyle === 'virtual-hosted-style') {
    if (isBucketHostedS3Endpoint(endpoint, bucket)) return endpoint;
    endpoint.hostname = `${bucket}.${endpoint.hostname}`;
    return endpoint;
  }

  return new URL(`${trimTrailingCharacter(endpoint.toString(), '/')}/${encodeURIComponent(bucket)}`);
}

function s3ObjectUrl(config: S3BackupDestination, objectKey: string): URL {
  return new URL(`${trimTrailingCharacter(s3BucketBaseUrl(config).toString(), '/')}/${encodePathSegments(objectKey)}`);
}

function normalizeS3ObjectKey(config: S3BackupDestination, relativePath: string): string {
  return buildJoinedPath(config.rootPath, normalizeRelativePath(relativePath));
}

async function signedS3Request(
  config: S3BackupDestination,
  method: 'GET' | 'PUT' | 'DELETE' | 'HEAD',
  url: URL,
  body?: Uint8Array,
  contentType?: string,
  signal?: AbortSignal
): Promise<Response> {
  const payloadHashHex = await sha256Hex(body || new Uint8Array());
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const headers: Record<string, string> = {
    host: url.host,
    'x-amz-content-sha256': payloadHashHex,
    'x-amz-date': amzDate,
  };
  if (method === 'PUT') headers['content-type'] = contentType || 'application/octet-stream';

  const authorization = await buildAwsV4Authorization(
    method,
    url,
    headers,
    payloadHashHex,
    config.accessKeyId,
    config.secretAccessKey,
    config.region || 'auto'
  );

  return fetch(url, {
    method,
    headers: {
      Authorization: authorization,
      'X-Amz-Content-Sha256': headers['x-amz-content-sha256'],
      'X-Amz-Date': headers['x-amz-date'],
      ...(method === 'PUT' ? { 'Content-Type': headers['content-type'] } : {}),
    },
    body,
    ...(signal ? { signal, redirect: 'error' as const } : {}),
  });
}

async function putToS3(
  config: S3BackupDestination,
  relativePath: string,
  bytes: Uint8Array,
  options: RemoteBackupFilePutOptions = {}
): Promise<void> {
  const objectKey = normalizeS3ObjectKey(config, relativePath);
  const url = s3ObjectUrl(config, objectKey);
  const response = await signedS3Request(config, 'PUT', url, bytes, options.contentType);

  if (!response.ok) {
    throw new Error(`S3 upload failed: ${response.status}`);
  }
}

async function uploadToS3(config: S3BackupDestination, archive: Uint8Array, fileName: string): Promise<BackupUploadResult> {
  await putToS3(config, fileName, archive, { contentType: 'application/zip' });
  return {
    provider: 's3',
    remotePath: normalizeS3ObjectKey(config, fileName),
  };
}

async function listS3Entries(
  config: S3BackupDestination,
  relativePath: string,
  signal: AbortSignal
): Promise<RemoteBackupListResult> {
  const currentPath = normalizeRelativePath(relativePath);
  const targetPrefixBase = normalizeS3ObjectKey(config, currentPath);
  const targetPrefix = trimSlashes(targetPrefixBase) ? `${trimSlashes(targetPrefixBase)}/` : '';
  const rootPrefix = trimSlashes(config.rootPath);
  const items: RemoteBackupItem[] = [];
  let continuationToken = '';
  const seenTokens = new Set<string>();
  let pageCount = 0;
  let entryCount = 0;

  do {
    if (++pageCount > REMOTE_LISTING_LIMITS.pages) throw new Error('Remote backup listing has too many pages');
    if (signal.aborted) throw new Error('Remote backup listing timed out');
    const url = s3BucketBaseUrl(config);
    url.searchParams.set('list-type', '2');
    url.searchParams.set('delimiter', '/');
    url.searchParams.set('max-keys', '1000');
    if (targetPrefix) url.searchParams.set('prefix', targetPrefix);
    if (continuationToken) url.searchParams.set('continuation-token', continuationToken);

    const response = await signedS3Request(config, 'GET', url, undefined, undefined, signal);
    if (!response.ok) {
      void response.body?.cancel().catch(() => undefined);
      throw new Error(`S3 listing failed: ${response.status}`);
    }

    const root = await readListingXml(response, signal);
    if (root.name !== 'ListBucketResult' || !['', 'http://s3.amazonaws.com/doc/2006-03-01/'].includes(root.namespace)) {
      throw new Error('Remote backup listing is not an S3 ListBucketResult');
    }
    const prefixes = listingChildren(root, 'CommonPrefixes');
    const contents = listingChildren(root, 'Contents');
    entryCount += prefixes.length + contents.length;
    if (entryCount > REMOTE_LISTING_LIMITS.entries) throw new Error('Remote backup listing has too many entries');

    for (const prefix of prefixes) {
      const fullPrefix = trimSlashes(listingText(prefix, 'Prefix'));
      if (!fullPrefix) continue;
      const relative = rootPrefix
        ? fullPrefix === rootPrefix
          ? ''
          : fullPrefix.startsWith(`${rootPrefix}/`)
            ? fullPrefix.slice(rootPrefix.length + 1)
            : ''
        : fullPrefix;
      const normalizedRelative = trimSlashes(relative);
      if (!normalizedRelative) continue;
      const itemPath = trimTrailingCharacter(normalizedRelative, '/');
      if ((parentPath(itemPath) || '') !== currentPath) continue;
      items.push({
        path: itemPath,
        name: basename(itemPath) || itemPath,
        isDirectory: true,
        size: null,
        modifiedAt: null,
      });
    }

    for (const content of contents) {
      const fullKey = trimSlashes(listingText(content, 'Key'));
      if (!fullKey || (targetPrefix && fullKey === trimSlashes(targetPrefix))) continue;
      const relative = rootPrefix
        ? fullKey.startsWith(`${rootPrefix}/`)
          ? fullKey.slice(rootPrefix.length + 1)
          : ''
        : fullKey;
      const normalizedRelative = trimSlashes(relative);
      if (!normalizedRelative || (parentPath(normalizedRelative) || '') !== currentPath) continue;
      items.push({
        path: normalizedRelative,
        name: basename(normalizedRelative) || normalizedRelative,
        isDirectory: false,
        size: Number(listingText(content, 'Size') || 0) || null,
        modifiedAt: parseHttpDate(listingText(content, 'LastModified')),
      });
    }

    continuationToken = listingText(root, 'NextContinuationToken');
    const isTruncated = listingText(root, 'IsTruncated');
    if (isTruncated !== 'true' && isTruncated !== 'false') {
      throw new Error('Remote backup listing has an invalid pagination status');
    }
    if (isTruncated === 'true' && !continuationToken) {
      throw new Error('Remote backup listing is truncated without a continuation token');
    }
    if (isTruncated === 'false' && continuationToken) {
      throw new Error('Remote backup listing has an unexpected continuation token');
    }
    if (continuationToken) {
      if (seenTokens.has(continuationToken)) throw new Error('Remote backup listing repeated a continuation token');
      seenTokens.add(continuationToken);
    }
  } while (continuationToken);

  const deduped = new Map<string, RemoteBackupItem>();
  for (const item of items) deduped.set(`${item.isDirectory ? 'd' : 'f'}:${item.path}`, item);

  return {
    provider: 's3',
    currentPath,
    parentPath: parentPath(currentPath),
    items: sortRemoteItems(Array.from(deduped.values())),
  };
}

async function downloadFromS3(config: S3BackupDestination, relativePath: string): Promise<RemoteBackupFile> {
  const normalized = normalizeRelativePath(relativePath);
  if (!normalized || normalized.endsWith('/')) {
    throw new Error('Please select a backup file');
  }
  const objectKey = normalizeS3ObjectKey(config, normalized);
  const url = s3ObjectUrl(config, objectKey);
  const response = await signedS3Request(config, 'GET', url);
  if (!response.ok) {
    throw new Error(`S3 download failed: ${response.status}`);
  }
  return {
    provider: 's3',
    remotePath: normalized,
    fileName: basename(normalized) || 'backup.zip',
    contentType: String(response.headers.get('Content-Type') || 'application/zip').trim() || 'application/zip',
    bytes: new Uint8Array(await response.arrayBuffer()),
  };
}

async function deleteFromS3(config: S3BackupDestination, relativePath: string): Promise<void> {
  const objectKey = normalizeS3ObjectKey(config, relativePath);
  const url = s3ObjectUrl(config, objectKey);
  const response = await signedS3Request(config, 'DELETE', url);
  if (!response.ok && response.status !== 404) {
    throw new Error(`S3 delete failed: ${response.status}`);
  }
}

async function existsInS3(config: S3BackupDestination, relativePath: string): Promise<boolean> {
  return (await statS3File(config, relativePath)) !== null;
}

async function statS3File(config: S3BackupDestination, relativePath: string): Promise<RemoteBackupFileStat | null> {
  const objectKey = normalizeS3ObjectKey(config, relativePath);
  const url = s3ObjectUrl(config, objectKey);
  const response = await signedS3Request(config, 'HEAD', url);
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`S3 existence check failed: ${response.status}`);
  }
  const size = Number(response.headers.get('Content-Length') || '');
  return {
    provider: 's3',
    remotePath: normalizeRelativePath(relativePath),
    size: Number.isFinite(size) ? size : null,
    modifiedAt: parseHttpDate(response.headers.get('Last-Modified') || ''),
  };
}

interface ConfiguredDestinationAdapter {
  provider: 'webdav' | 's3';
  config: WebDavBackupDestination | S3BackupDestination;
  upload: (config: WebDavBackupDestination | S3BackupDestination, archive: Uint8Array, fileName: string) => Promise<BackupUploadResult>;
  putFile: (config: WebDavBackupDestination | S3BackupDestination, relativePath: string, bytes: Uint8Array, options?: RemoteBackupFilePutOptions) => Promise<void>;
  list: (config: WebDavBackupDestination | S3BackupDestination, relativePath: string) => Promise<RemoteBackupListResult>;
  download: (config: WebDavBackupDestination | S3BackupDestination, relativePath: string) => Promise<RemoteBackupFile>;
  deleteFile: (config: WebDavBackupDestination | S3BackupDestination, relativePath: string) => Promise<void>;
  exists: (config: WebDavBackupDestination | S3BackupDestination, relativePath: string) => Promise<boolean>;
  stat: (config: WebDavBackupDestination | S3BackupDestination, relativePath: string) => Promise<RemoteBackupFileStat | null>;
}

export interface RemoteBackupTransferSession {
  provider: BackupDestinationType;
  uploadArchive(archive: Uint8Array, fileName: string): Promise<BackupUploadResult>;
  putFile(relativePath: string, bytes: Uint8Array, options?: RemoteBackupFilePutOptions): Promise<void>;
  list(relativePath: string): Promise<RemoteBackupListResult>;
  download(relativePath: string): Promise<RemoteBackupFile>;
  deleteFile(relativePath: string): Promise<void>;
  exists(relativePath: string): Promise<boolean>;
  stat(relativePath: string): Promise<RemoteBackupFileStat | null>;
}

function resolveConfiguredDestinationAdapter(
  destination: BackupDestinationRecord
): ConfiguredDestinationAdapter {
  ensureDestinationConfigReady(destination);

  if (destination.type === 'webdav') {
    return {
      provider: 'webdav',
      config: destination.destination as WebDavBackupDestination,
      upload: (config, archive, fileName) => uploadToWebDav(config as WebDavBackupDestination, archive, fileName),
      putFile: (config, relativePath, bytes, options) => putToWebDav(config as WebDavBackupDestination, relativePath, bytes, options),
      list: (config, relativePath) => withListingDeadline((signal) => listWebDavEntries(config as WebDavBackupDestination, relativePath, signal)),
      download: (config, relativePath) => downloadFromWebDav(config as WebDavBackupDestination, relativePath),
      deleteFile: (config, relativePath) => deleteFromWebDav(config as WebDavBackupDestination, relativePath),
      exists: (config, relativePath) => existsInWebDav(config as WebDavBackupDestination, relativePath),
      stat: (config, relativePath) => statWebDavFile(config as WebDavBackupDestination, relativePath),
    };
  }
  if (destination.type === 's3') {
    return {
      provider: 's3',
      config: destination.destination as S3BackupDestination,
      upload: (config, archive, fileName) => uploadToS3(config as S3BackupDestination, archive, fileName),
      putFile: (config, relativePath, bytes, options) => putToS3(config as S3BackupDestination, relativePath, bytes, options),
      list: (config, relativePath) => withListingDeadline((signal) => listS3Entries(config as S3BackupDestination, relativePath, signal)),
      download: (config, relativePath) => downloadFromS3(config as S3BackupDestination, relativePath),
      deleteFile: (config, relativePath) => deleteFromS3(config as S3BackupDestination, relativePath),
      exists: (config, relativePath) => existsInS3(config as S3BackupDestination, relativePath),
      stat: (config, relativePath) => statS3File(config as S3BackupDestination, relativePath),
    };
  }

  throw new Error('Unsupported backup destination type');
}

export function createRemoteBackupTransferSession(destination: BackupDestinationRecord): RemoteBackupTransferSession {
  const adapter = resolveConfiguredDestinationAdapter(destination);
  const ensuredDirectories = adapter.provider === 'webdav' ? new Set<string>() : null;

  const putFile = async (relativePath: string, bytes: Uint8Array, options: RemoteBackupFilePutOptions = {}): Promise<void> => {
    const normalized = normalizeRelativePath(relativePath);
    if (adapter.provider === 'webdav' && ensuredDirectories) {
      await putToWebDav(adapter.config as WebDavBackupDestination, normalized, bytes, options, ensuredDirectories);
      return;
    }
    await adapter.putFile(adapter.config, normalized, bytes, options);
  };

  return {
    provider: adapter.provider,
    uploadArchive: async (archive: Uint8Array, fileName: string) => {
      await putFile(fileName, archive, { contentType: 'application/zip' });
      return {
        provider: adapter.provider,
        remotePath: adapter.provider === 'webdav'
          ? buildJoinedPath((adapter.config as WebDavBackupDestination).remotePath, fileName)
          : normalizeS3ObjectKey(adapter.config as S3BackupDestination, fileName),
      };
    },
    putFile,
    list: async (relativePath: string) => adapter.list(adapter.config, relativePath),
    download: async (relativePath: string) => adapter.download(adapter.config, relativePath),
    deleteFile: async (relativePath: string) => adapter.deleteFile(adapter.config, normalizeRelativePath(relativePath)),
    exists: async (relativePath: string) => adapter.exists(adapter.config, normalizeRelativePath(relativePath)),
    stat: async (relativePath: string) => adapter.stat(adapter.config, normalizeRelativePath(relativePath)),
  };
}

export async function uploadBackupArchive(
  destination: BackupDestinationRecord,
  archive: Uint8Array,
  fileName: string
): Promise<BackupUploadResult> {
  return createRemoteBackupTransferSession(destination).uploadArchive(archive, fileName);
}

export async function listRemoteBackupEntries(destination: BackupDestinationRecord, relativePath: string): Promise<RemoteBackupListResult> {
  return createRemoteBackupTransferSession(destination).list(relativePath);
}

export async function downloadRemoteBackupFile(destination: BackupDestinationRecord, relativePath: string): Promise<RemoteBackupFile> {
  return createRemoteBackupTransferSession(destination).download(relativePath);
}

export async function deleteRemoteBackupFile(destination: BackupDestinationRecord, relativePath: string): Promise<void> {
  const normalized = ensureRemoteRestoreCandidate(relativePath);
  await createRemoteBackupTransferSession(destination).deleteFile(normalized);
}

export async function remoteBackupFileExists(destination: BackupDestinationRecord, relativePath: string): Promise<boolean> {
  const normalized = normalizeRelativePath(relativePath);
  return createRemoteBackupTransferSession(destination).exists(normalized);
}

export async function uploadRemoteBackupFile(
  destination: BackupDestinationRecord,
  relativePath: string,
  bytes: Uint8Array,
  options: RemoteBackupFilePutOptions = {}
): Promise<void> {
  const normalized = normalizeRelativePath(relativePath);
  await createRemoteBackupTransferSession(destination).putFile(normalized, bytes, options);
}

function compareBackupItemsByRecency(a: RemoteBackupItem, b: RemoteBackupItem, preferredFileName?: string): number {
  if (preferredFileName) {
    const aPreferred = a.name === preferredFileName ? 1 : 0;
    const bPreferred = b.name === preferredFileName ? 1 : 0;
    if (aPreferred !== bPreferred) return bPreferred - aPreferred;
  }
  const aTime = a.modifiedAt ? new Date(a.modifiedAt).getTime() : 0;
  const bTime = b.modifiedAt ? new Date(b.modifiedAt).getTime() : 0;
  if (aTime !== bTime) return bTime - aTime;
  return b.name.localeCompare(a.name, 'en');
}

export async function pruneRemoteBackupArchives(
  destination: BackupDestinationRecord,
  retentionCount: number | null,
  preferredFileName?: string
): Promise<number> {
  if (retentionCount === null) return 0;
  const adapter = resolveConfiguredDestinationAdapter(destination);
  const listing = await adapter.list(adapter.config, '');
  const backupFiles = listing.items
    .filter((item) => !item.isDirectory && isBackupArchiveName(item.name))
    .sort((a, b) => compareBackupItemsByRecency(a, b, preferredFileName));
  if (backupFiles.length <= retentionCount) return 0;
  for (const item of backupFiles.slice(retentionCount)) {
    await adapter.deleteFile(adapter.config, item.path);
  }
  return backupFiles.length - retentionCount;
}

export function ensureRemoteRestoreCandidate(relativePath: string): string {
  const normalized = normalizeRelativePath(relativePath);
  if (!normalized || !/\.zip$/i.test(normalized)) {
    throw new Error('Please select a backup ZIP file');
  }
  return normalized;
}

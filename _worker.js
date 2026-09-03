/**
 * Cloudflare KV manager for one internal Cloudflare account.
 *
 * Required secrets:
 * - CF_ACCOUNT_ID: Cloudflare account ID
 * - CF_API_TOKEN: Account-scoped API Token with Workers KV Storage Write
 * - ADMIN_PASSWORD: password used by this small admin UI
 * - SESSION_SECRET: random string (at least 32 characters) used to encrypt sessions
 *
 * Optional secret:
 * - ALLOWED_NAMESPACE_IDS: comma-separated namespace IDs allowed in this UI
 */

const CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4";
const CLOUDFLARE_API_ORIGIN = "https://api.cloudflare.com";
const CLOUDFLARE_API_PATH_PREFIX = "/client/v4/";
const MAX_TRUSTED_CLOUDFLARE_API_REDIRECTS = 1;
const CLOUDFLARE_REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
// `__Host-` prevents a sibling subdomain from setting a conflicting session cookie.
const SESSION_COOKIE_NAME = "__Host-kv_manager_session";
const SESSION_VERSION = 1;
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_EDITABLE_VALUE_BYTES = 1024 * 1024;
// A JSON string can expand a one-byte control character to six ASCII bytes.
const MAX_JSON_BODY_BYTES = MAX_EDITABLE_VALUE_BYTES * 6 + 32 * 1024;
const MAX_LOGIN_BODY_BYTES = 4 * 1024;
const MINIMUM_PRESERVED_EXPIRATION_SECONDS = 60;
const MAX_KEY_BYTES = 512;
const NAMESPACE_PAGE_SIZE = 100;
const KEY_PAGE_SIZE = 100;
const CLOUDFLARE_API_OPERATIONS = Object.freeze({
  LIST_NAMESPACES: "list_namespaces",
  LIST_KEYS: "list_keys",
  READ_VALUE: "read_value",
  READ_METADATA: "read_metadata",
  CHECK_EXISTING_VALUE: "check_existing_value",
  CHECK_EXISTING_METADATA: "check_existing_metadata",
  CHECK_CREATE_VALUE: "check_create_value",
  WRITE_VALUE: "write_value",
  CREATE_VALUE: "create_value",
  DELETE_VALUE: "delete_value",
});

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.protocol !== "https:") {
      return insecureTransportResponse(request, url);
    }

    if (url.pathname.startsWith("/api/")) {
      return handleApiRequest(request, env, url);
    }

    return handlePageRequest(request, env, url);
  },
};

async function handlePageRequest(request, env, url) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return methodNotAllowed(["GET", "HEAD"]);
  }

  if (url.pathname === "/" || url.pathname === "/index.html") {
    return appResponse(request.method === "HEAD");
  }

  // This keeps Pages Advanced Mode compatible with additional static assets.
  if (env.ASSETS && typeof env.ASSETS.fetch === "function") {
    return env.ASSETS.fetch(request);
  }

  return notFoundResponse();
}

async function handleApiRequest(request, env, url) {
  try {
    const { pathname } = url;

    if (pathname === "/api/session") {
      if (request.method === "GET") {
        return await getSessionStatus(request, env);
      }
      if (request.method === "POST") {
        return await createSession(request, env);
      }
      if (request.method === "DELETE") {
        return await deleteSession(request);
      }
      return methodNotAllowed(["GET", "POST", "DELETE"]);
    }

    if (pathname === "/api/namespaces" && request.method === "GET") {
      const config = getConfiguration(env);
      await requireSession(request, config);
      return await listNamespaces(url, config);
    }

    if (pathname === "/api/keys" && request.method === "GET") {
      const config = getConfiguration(env);
      await requireSession(request, config);
      return await listKeys(url, config);
    }

    if (pathname === "/api/value" && request.method === "GET") {
      const config = getConfiguration(env);
      await requireSession(request, config);
      return await readValue(url, config);
    }

    if (pathname === "/api/value" && request.method === "PUT") {
      assertSameOrigin(request);
      const config = getConfiguration(env);
      await requireSession(request, config);
      return await writeValue(request, config);
    }

    if (pathname === "/api/value" && request.method === "POST") {
      assertSameOrigin(request);
      const config = getConfiguration(env);
      await requireSession(request, config);
      return await createValue(request, config);
    }

    if (pathname === "/api/value" && request.method === "DELETE") {
      assertSameOrigin(request);
      const config = getConfiguration(env);
      await requireSession(request, config);
      return await deleteValue(request, config);
    }

    if (
      pathname === "/api/namespaces" ||
      pathname === "/api/keys" ||
      pathname === "/api/value"
    ) {
      return methodNotAllowed(
        pathname === "/api/value" ? ["GET", "POST", "PUT", "DELETE"] : ["GET"],
      );
    }

    return notFoundResponse();
  } catch (error) {
    return errorResponse(error);
  }
}

async function getSessionStatus(request, env) {
  if (!getCookie(request.headers.get("Cookie"), SESSION_COOKIE_NAME)) {
    return jsonResponse({ authenticated: false });
  }

  const config = getConfiguration(env);
  const session = await readSession(request, config.sessionSecret);
  return jsonResponse({ authenticated: Boolean(session) });
}

async function createSession(request, env) {
  assertSameOrigin(request);
  const config = getConfiguration(env);
  const body = await readJsonBody(request, MAX_LOGIN_BODY_BYTES);
  const password = typeof body.password === "string" ? body.password : "";

  if (!(await constantTimeEqual(password, config.adminPassword))) {
    throw new HttpError(401, "登录密码不正确。");
  }

  const token = await encryptSession(config.sessionSecret);
  return jsonResponse(
    { authenticated: true },
    200,
    { "Set-Cookie": sessionCookie(token) },
  );
}

async function deleteSession(request) {
  assertSameOrigin(request);
  return jsonResponse(
    { authenticated: false },
    200,
    { "Set-Cookie": expiredSessionCookie() },
  );
}

async function listNamespaces(url, config) {
  const page = parsePage(url.searchParams.get("page"));
  const query = new URLSearchParams({
    page: String(page),
    per_page: String(NAMESPACE_PAGE_SIZE),
    order: "title",
    direction: "asc",
  });
  const response = await cloudflareFetch(
    config,
    CLOUDFLARE_API_OPERATIONS.LIST_NAMESPACES,
    `/accounts/${config.accountId}/storage/kv/namespaces?${query.toString()}`,
  );
  const payload = await readCloudflareJson(response);
  const allowedNamespaceIds = config.allowedNamespaceIds;
  const items = Array.isArray(payload.result) ? payload.result : [];
  const visibleItems = items
    .filter((item) => item && typeof item.id === "string")
    .filter((item) => !allowedNamespaceIds || allowedNamespaceIds.has(item.id))
    .map((item) => ({
      id: item.id,
      title: typeof item.title === "string" ? item.title : item.id,
      jurisdiction: typeof item.jurisdiction === "string" ? item.jurisdiction : null,
    }));
  const resultInfo = payload.result_info || {};
  const totalCount = Number(resultInfo.total_count);
  const currentPage = Number(resultInfo.page) || page;
  const perPage = Number(resultInfo.per_page) || NAMESPACE_PAGE_SIZE;
  const nextPage =
    Number.isFinite(totalCount) && currentPage * perPage < totalCount
      ? currentPage + 1
      : null;

  return jsonResponse({ items: visibleItems, nextPage });
}

async function listKeys(url, config) {
  const namespaceId = readNamespaceId(url.searchParams.get("namespaceId"), config);
  const cursor = url.searchParams.get("cursor");
  const prefix = url.searchParams.get("prefix") || "";

  if (cursor && cursor.length > 2048) {
    throw new HttpError(400, "分页游标无效。");
  }
  if (byteLength(prefix) > MAX_KEY_BYTES || hasControlCharacter(prefix)) {
    throw new HttpError(400, "键前缀无效。");
  }

  const query = new URLSearchParams({ limit: String(KEY_PAGE_SIZE) });
  if (cursor) {
    query.set("cursor", cursor);
  }
  if (prefix) {
    query.set("prefix", prefix);
  }

  const response = await cloudflareFetch(
    config,
    CLOUDFLARE_API_OPERATIONS.LIST_KEYS,
    `${namespacePath(config, namespaceId)}/keys?${query.toString()}`,
  );
  const payload = await readCloudflareJson(response);
  const items = Array.isArray(payload.result) ? payload.result : [];

  return jsonResponse({
    items: items
      .filter((item) => item && typeof item.name === "string")
      .map((item) => ({
        name: item.name,
        expiration: normalizeExpiration(item.expiration),
      })),
    cursor:
      payload.result_info && typeof payload.result_info.cursor === "string"
        ? payload.result_info.cursor
        : null,
  });
}

async function readValue(url, config) {
  const namespaceId = readNamespaceId(url.searchParams.get("namespaceId"), config);
  const key = readKey(url.searchParams.get("key"));
  const valuePath = `${namespacePath(config, namespaceId)}/values/${encodeKeyPathSegment(key)}`;
  const metadataPath = `${namespacePath(config, namespaceId)}/metadata/${encodeKeyPathSegment(key)}`;

  const [valueResponse, metadataResponse] = await Promise.all([
    cloudflareFetch(config, CLOUDFLARE_API_OPERATIONS.READ_VALUE, valuePath),
    cloudflareFetch(config, CLOUDFLARE_API_OPERATIONS.READ_METADATA, metadataPath),
  ]);
  await ensureCloudflareSuccess(valueResponse);
  const metadataPayload = await readCloudflareJson(metadataResponse);
  const expiration = normalizeExpiration(valueResponse.headers.get("expiration"));
  const value = await readUtf8Text(valueResponse, MAX_EDITABLE_VALUE_BYTES);

  return jsonResponse({
    value,
    expiration,
    hasMetadata:
      metadataPayload.result !== undefined && metadataPayload.result !== null,
  });
}

async function writeValue(request, config) {
  const body = await readJsonBody(request);
  const namespaceId = readNamespaceId(body.namespaceId, config);
  const key = readKey(body.key);
  const value = readEditableTextValue(body.value);

  // The Cloudflare PUT API clears metadata and expiration when they are omitted.
  // Re-read them immediately before saving instead of trusting stale browser state.
  // This reduces loss risk but cannot provide an atomic compare-and-swap guarantee.
  const existingAttributes = await readExistingAttributes(config, namespaceId, key);
  if (!existingAttributes.exists) {
    throw new HttpError(
      404,
      "键不存在或尚未同步到列表。为避免意外创建，请刷新后重新选择该键。",
    );
  }
  if (
    existingAttributes.expiration !== null &&
    existingAttributes.expiration <=
      Math.floor(Date.now() / 1000) + MINIMUM_PRESERVED_EXPIRATION_SECONDS
  ) {
    throw new HttpError(
      409,
      "该键将在 60 秒内过期，不能在不改变过期策略的情况下安全保存。",
    );
  }
  const formData = valueFormData(value, existingAttributes.metadata);

  const endpoint = new URL(
    `${CLOUDFLARE_API_BASE}${namespacePath(config, namespaceId)}/values/${encodeKeyPathSegment(key)}`,
  );
  if (existingAttributes.expiration !== null) {
    endpoint.searchParams.set("expiration", String(existingAttributes.expiration));
  }

  const response = await cloudflareFetch(config, CLOUDFLARE_API_OPERATIONS.WRITE_VALUE, endpoint, {
    method: "PUT",
    body: formData,
  });
  await readCloudflareJson(response);

  return jsonResponse({
    saved: true,
    preservedExpiration: existingAttributes.expiration,
    preservedMetadata:
      existingAttributes.metadata !== undefined &&
      existingAttributes.metadata !== null,
  });
}

async function createValue(request, config) {
  const body = await readJsonBody(request);
  const namespaceId = readNamespaceId(body.namespaceId, config);
  const key = readKey(body.key);
  const value = readEditableTextValue(body.value);

  // The KV write API is an unconditional PUT. Check first so ordinary duplicate
  // creation attempts fail instead of overwriting an existing key. This remains
  // non-atomic: a concurrent creator can write between this read and the PUT.
  if (await keyExists(config, namespaceId, key)) {
    throw new HttpError(409, "键已存在，请在列表中选择该键后修改。");
  }

  const endpoint = `${namespacePath(config, namespaceId)}/values/${encodeKeyPathSegment(key)}`;
  const response = await cloudflareFetch(
    config,
    CLOUDFLARE_API_OPERATIONS.CREATE_VALUE,
    endpoint,
    {
      method: "PUT",
      // New keys intentionally start without metadata or an expiration policy.
      body: valueFormData(value),
    },
  );
  await readCloudflareJson(response);

  return jsonResponse({ created: true }, 201);
}

async function deleteValue(request, config) {
  const body = await readJsonBody(request);
  const namespaceId = readNamespaceId(body.namespaceId, config);
  const key = readKey(body.key);

  // The browser asks the user to type the full key name. Keep this check on the
  // server too; client-side confirmation is not an authorization boundary.
  if (body.confirmation !== key) {
    throw new HttpError(400, "请输入完整键名以确认删除。");
  }

  const response = await cloudflareFetch(
    config,
    CLOUDFLARE_API_OPERATIONS.DELETE_VALUE,
    `${namespacePath(config, namespaceId)}/values/${encodeKeyPathSegment(key)}`,
    { method: "DELETE" },
  );
  await readCloudflareJson(response);

  return jsonResponse({ deleted: true });
}

function readEditableTextValue(value) {
  if (typeof value !== "string") {
    throw new HttpError(400, "值必须是文本。");
  }
  if (hasUnpairedSurrogate(value)) {
    throw new HttpError(400, "值包含无效的 Unicode 代理项，不能安全保存。");
  }
  if (byteLength(value) > MAX_EDITABLE_VALUE_BYTES) {
    throw new HttpError(
      413,
      `编辑器只允许保存不超过 ${MAX_EDITABLE_VALUE_BYTES / 1024 / 1024} MiB 的 UTF-8 文本。`,
    );
  }
  return value;
}

function valueFormData(value, metadata) {
  // A string FormData field can normalize line endings. A Blob is an Uploadable
  // value part, so its UTF-8 bytes are sent exactly as encoded here.
  const formData = new FormData();
  formData.set(
    "value",
    new Blob([encoder.encode(value)], { type: "text/plain;charset=utf-8" }),
    "value",
  );
  if (metadata !== undefined && metadata !== null) {
    formData.set("metadata", JSON.stringify(metadata));
  }
  return formData;
}

async function keyExists(config, namespaceId, key) {
  const response = await cloudflareFetch(
    config,
    CLOUDFLARE_API_OPERATIONS.CHECK_CREATE_VALUE,
    `${namespacePath(config, namespaceId)}/values/${encodeKeyPathSegment(key)}`,
  );

  if (response.status === 404) {
    await discardResponseBody(response);
    return false;
  }

  await ensureCloudflareSuccess(response);
  await discardResponseBody(response);
  return true;
}

async function readExistingAttributes(config, namespaceId, key) {
  const encodedKey = encodeKeyPathSegment(key);
  const basePath = namespacePath(config, namespaceId);
  const valueResponse = await cloudflareFetch(
    config,
    CLOUDFLARE_API_OPERATIONS.CHECK_EXISTING_VALUE,
    `${basePath}/values/${encodedKey}`,
  );

  if (valueResponse.status === 404) {
    await discardResponseBody(valueResponse);
    return { exists: false, expiration: null, metadata: undefined };
  }

  await ensureCloudflareSuccess(valueResponse);
  const expiration = normalizeExpiration(valueResponse.headers.get("expiration"));
  await discardResponseBody(valueResponse);

  const metadataResponse = await cloudflareFetch(
    config,
    CLOUDFLARE_API_OPERATIONS.CHECK_EXISTING_METADATA,
    `${basePath}/metadata/${encodedKey}`,
  );
  const metadataPayload = await readCloudflareJson(metadataResponse);

  return {
    exists: true,
    expiration,
    metadata: metadataPayload.result,
  };
}

function getConfiguration(env) {
  const accountId = requireSecret(env, "CF_ACCOUNT_ID").toLowerCase();
  const apiToken = requireSecret(env, "CF_API_TOKEN");
  const adminPassword = requireSecret(env, "ADMIN_PASSWORD");
  const sessionSecret = requireSecret(env, "SESSION_SECRET");

  if (!isIdentifier(accountId)) {
    throw new HttpError(500, "服务器配置无效。");
  }
  if (adminPassword.length < 2 || sessionSecret.length < 32) {
    throw new HttpError(500, "服务器配置无效。");
  }

  return {
    accountId,
    apiToken,
    adminPassword,
    sessionSecret,
    allowedNamespaceIds: parseAllowedNamespaceIds(env.ALLOWED_NAMESPACE_IDS),
  };
}

function requireSecret(env, name) {
  const value = env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(500, "服务器尚未配置完成。");
  }
  return value;
}

function parseAllowedNamespaceIds(value) {
  if (typeof value !== "string" || value.trim() === "") {
    return null;
  }

  const ids = value
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (ids.length === 0 || ids.some((id) => !isIdentifier(id))) {
    throw new HttpError(500, "服务器配置无效。");
  }
  return new Set(ids);
}

async function requireSession(request, config) {
  const session = await readSession(request, config.sessionSecret);
  if (!session) {
    throw new HttpError(401, "登录已过期，请重新登录。");
  }
  return session;
}

async function readSession(request, sessionSecret) {
  const token = getCookie(request.headers.get("Cookie"), SESSION_COOKIE_NAME);
  if (!token) {
    return null;
  }

  try {
    const parts = token.split(".");
    if (parts.length !== 3 || parts[0] !== `v${SESSION_VERSION}`) {
      return null;
    }

    const iv = base64UrlToBytes(parts[1]);
    const ciphertext = base64UrlToBytes(parts[2]);
    if (iv.byteLength !== 12 || ciphertext.byteLength === 0) {
      return null;
    }

    const key = await sessionEncryptionKey(sessionSecret);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext,
    );
    const payload = JSON.parse(decoder.decode(plaintext));
    if (
      !payload ||
      payload.v !== SESSION_VERSION ||
      !Number.isSafeInteger(payload.exp) ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

async function encryptSession(sessionSecret) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = JSON.stringify({
    v: SESSION_VERSION,
    iat: issuedAt,
    exp: issuedAt + SESSION_TTL_SECONDS,
  });
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await sessionEncryptionKey(sessionSecret),
    encoder.encode(payload),
  );

  return `v${SESSION_VERSION}.${bytesToBase64Url(iv)}.${bytesToBase64Url(new Uint8Array(ciphertext))}`;
}

async function sessionEncryptionKey(sessionSecret) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(sessionSecret));
  return crypto.subtle.importKey(
    "raw",
    digest,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

async function constantTimeEqual(left, right) {
  const [leftDigest, rightDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right)),
  ]);
  const leftBytes = new Uint8Array(leftDigest);
  const rightBytes = new Uint8Array(rightDigest);
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  return difference === 0;
}

function sessionCookie(token) {
  return `${SESSION_COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=${SESSION_TTL_SECONDS}`;
}

function expiredSessionCookie() {
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0`;
}

function getCookie(cookieHeader, name) {
  if (!cookieHeader) {
    return null;
  }
  const prefix = `${name}=`;
  for (const item of cookieHeader.split(";")) {
    const trimmed = item.trim();
    if (trimmed.startsWith(prefix)) {
      return trimmed.slice(prefix.length);
    }
  }
  return null;
}

async function cloudflareFetch(config, operation, pathOrUrl, init = {}) {
  const url =
    pathOrUrl instanceof URL
      ? pathOrUrl
      : new URL(`${CLOUDFLARE_API_BASE}${pathOrUrl}`);
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${config.apiToken}`);
  const method = normalizeRequestMethod(init.method);
  let currentUrl = url;

  for (
    let redirectCount = 0;
    redirectCount <= MAX_TRUSTED_CLOUDFLARE_API_REDIRECTS;
    redirectCount += 1
  ) {
    let response;
    try {
      response = await fetch(currentUrl, {
        ...init,
        headers: new Headers(headers),
        redirect: "manual",
      });
    } catch (error) {
      logCloudflareFetchFailure(operation, method, error);
      throw new HttpError(502, "无法连接 Cloudflare API。");
    }

    if (!isRedirectStatus(response.status)) {
      return response;
    }

    await discardResponseBody(response);
    if (method !== "GET") {
      logCloudflareRedirectRejected(operation, method, response.status, "non_get");
      throw new HttpError(502, "Cloudflare API 变更请求发生重定向，未自动重试。");
    }
    if (redirectCount === MAX_TRUSTED_CLOUDFLARE_API_REDIRECTS) {
      logCloudflareRedirectRejected(operation, method, response.status, "too_many_redirects");
      throw new HttpError(502, "Cloudflare API 重定向次数超出安全上限。");
    }

    const redirect = resolveTrustedCloudflareRedirect(
      response.headers.get("location"),
      currentUrl,
      config.accountId,
    );
    if (!redirect.url) {
      logCloudflareRedirectRejected(operation, method, response.status, redirect.targetClass);
      throw new HttpError(502, "Cloudflare API 返回了不受信任的重定向。");
    }
    currentUrl = redirect.url;
  }

  throw new HttpError(502, "Cloudflare API 重定向次数超出安全上限。");
}

function normalizeRequestMethod(method) {
  return typeof method === "string" ? method.toUpperCase() : "GET";
}

function isRedirectStatus(status) {
  return CLOUDFLARE_REDIRECT_STATUSES.has(status);
}

function resolveTrustedCloudflareRedirect(location, currentUrl, accountId) {
  if (!location) {
    return { url: null, targetClass: "missing" };
  }

  try {
    const target = new URL(location, currentUrl);
    const accountKvPathPrefix =
      `${CLOUDFLARE_API_PATH_PREFIX}accounts/${accountId}/storage/kv/`;
    const isTrusted =
      target.origin === CLOUDFLARE_API_ORIGIN &&
      target.username === "" &&
      target.password === "" &&
      target.pathname.startsWith(accountKvPathPrefix);
    return isTrusted
      ? { url: target, targetClass: "same_api_origin" }
      : { url: null, targetClass: "other_or_invalid" };
  } catch {
    return { url: null, targetClass: "other_or_invalid" };
  }
}

function logCloudflareRedirectRejected(operation, method, status, targetClass) {
  const diagnostic = JSON.stringify({
    event: "cloudflare_api_redirect_rejected",
    operation,
    method: diagnosticRequestMethod(method),
    status,
    target_class: targetClass,
  });

  try {
    // Do not log the redirect Location, URL, headers, or any request configuration.
    console.error(diagnostic);
  } catch {
    // Logging failure must not replace the original, generic 502 response.
  }
}

function logCloudflareFetchFailure(operation, method, error) {
  const diagnostic = JSON.stringify({
    event: "cloudflare_api_fetch_rejected",
    operation,
    method: diagnosticRequestMethod(method),
    error_category: cloudflareFetchErrorCategory(error),
  });

  try {
    // Keep this log fully static: never send the original error, URL, headers,
    // request body, or configuration into Workers Logs.
    console.error(diagnostic);
  } catch {
    // Logging failure must not replace the original, generic 502 response.
  }
}

function diagnosticRequestMethod(method) {
  if (method === "GET" || method === "POST" || method === "PUT" || method === "DELETE") {
    return method;
  }
  return "OTHER";
}

function cloudflareFetchErrorCategory(error) {
  const message = errorProperty(error, "message").toLowerCase();
  if (message.includes("network connection lost")) {
    return "network_connection_lost";
  }
  if (message.includes("cloudflare-owned") || /\b1024\b/u.test(message)) {
    return "cloudflare_owned_ip";
  }
  if (message.includes("redirect")) {
    return "redirect_rejected";
  }
  if (message.includes("dns")) {
    return "dns_failure";
  }
  if (message.includes("tls") || message.includes("certificate")) {
    return "tls_failure";
  }

  if (error instanceof TypeError) {
    return "type_error";
  }

  const name = errorProperty(error, "name");
  if (name === "AbortError") {
    return "abort_error";
  }
  if (name === "TimeoutError") {
    return "timeout_error";
  }
  return "unknown_error";
}

function errorProperty(error, property) {
  try {
    if (!error || (typeof error !== "object" && typeof error !== "function")) {
      return "";
    }
    const value = error[property];
    return typeof value === "string" ? value : "";
  } catch {
    return "";
  }
}

async function ensureCloudflareSuccess(response) {
  if (response.ok) {
    return;
  }
  await discardResponseBody(response);
  throw cloudflareError(response.status);
}

async function readCloudflareJson(response) {
  await ensureCloudflareSuccess(response);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new HttpError(502, "Cloudflare API 返回了无法识别的响应。");
  }
  if (!payload || payload.success !== true) {
    throw new HttpError(502, "Cloudflare API 未完成请求。");
  }
  return payload;
}

function cloudflareError(status) {
  if (status === 401 || status === 403) {
    return new HttpError(502, "Cloudflare API Token 被拒绝，请检查权限和账号范围。");
  }
  if (status === 404) {
    return new HttpError(404, "未找到对应的 KV 命名空间或键。");
  }
  if (status === 429) {
    return new HttpError(429, "Cloudflare API 限流，请稍后重试。");
  }
  if (status >= 500) {
    return new HttpError(502, "Cloudflare API 暂时不可用，请稍后重试。");
  }
  return new HttpError(502, `Cloudflare API 拒绝了请求（HTTP ${status}）。`);
}

async function discardResponseBody(response) {
  if (!response.body) {
    return;
  }
  try {
    await response.body.cancel();
  } catch {
    // Nothing useful can be done here; the original API error is retained.
  }
}

async function readUtf8Text(response, maximumBytes) {
  const bytes = await readBodyBytes(
    response,
    maximumBytes,
    `该值超过编辑器 ${maximumBytes / 1024 / 1024} MiB 的文本上限。`,
  );

  try {
    // `ignoreBOM: true` retains a leading U+FEFF instead of silently stripping it.
    // That makes a read/edit/save round trip lossless for BOM-prefixed text files.
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new HttpError(415, "该键的值不是 UTF-8 文本，不能在此编辑器中修改。");
  }
}

async function readBodyBytes(message, maximumBytes, tooLargeMessage) {
  const contentLength = Number(message.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > maximumBytes) {
    await discardResponseBody(message);
    throw new HttpError(413, tooLargeMessage);
  }
  if (!message.body) {
    return new Uint8Array();
  }

  const reader = message.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      totalBytes += value.byteLength;
      if (totalBytes > maximumBytes) {
        try {
          await reader.cancel();
        } catch {
          // The size error remains the correct response even if cancellation fails.
        }
        throw new HttpError(413, tooLargeMessage);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function readJsonBody(request, maximumBytes = MAX_JSON_BODY_BYTES) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new HttpError(415, "请求必须使用 application/json。");
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(
      await readBodyBytes(request, maximumBytes, "请求内容过大。"),
    );
  } catch (error) {
    if (error instanceof HttpError) {
      throw error;
    }
    throw new HttpError(400, "请求必须是有效的 UTF-8 JSON。");
  }
  try {
    const payload = JSON.parse(text);
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("invalid payload");
    }
    return payload;
  } catch {
    throw new HttpError(400, "请求 JSON 无效。");
  }
}

function assertSameOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin || origin !== new URL(request.url).origin) {
    throw new HttpError(403, "跨站请求已被拒绝。");
  }
}

function readNamespaceId(value, config) {
  const namespaceId = typeof value === "string" ? value.toLowerCase() : "";
  if (!isIdentifier(namespaceId)) {
    throw new HttpError(400, "KV 命名空间 ID 无效。");
  }
  if (config.allowedNamespaceIds && !config.allowedNamespaceIds.has(namespaceId)) {
    throw new HttpError(403, "此 KV 命名空间不在允许范围内。");
  }
  return namespaceId;
}

function readKey(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(400, "键不能为空。");
  }
  if (value === "." || value === "..") {
    throw new HttpError(400, "键不能是路径保留名称。");
  }
  if (byteLength(value) > MAX_KEY_BYTES) {
    throw new HttpError(400, `键不能超过 ${MAX_KEY_BYTES} 字节。`);
  }
  if (hasUnpairedSurrogate(value) || hasControlCharacter(value)) {
    throw new HttpError(400, "键包含不支持的控制字符或 Unicode 代理项。");
  }
  return value;
}

function parsePage(value) {
  if (value === null || value === "") {
    return 1;
  }
  const page = Number(value);
  if (!Number.isSafeInteger(page) || page < 1 || page > 100000) {
    throw new HttpError(400, "页码无效。");
  }
  return page;
}

function namespacePath(config, namespaceId) {
  return `/accounts/${config.accountId}/storage/kv/namespaces/${namespaceId}`;
}

function encodeKeyPathSegment(key) {
  return encodeURIComponent(key).replace(/[!'()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function normalizeExpiration(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  const expiration = Number(value);
  return Number.isSafeInteger(expiration) && expiration > 0 ? expiration : null;
}

function isIdentifier(value) {
  return typeof value === "string" && /^[a-f0-9]{32}$/iu.test(value);
}

function hasControlCharacter(value) {
  return /[\u0000-\u001F\u007F-\u009F]/u.test(value);
}

function byteLength(value) {
  return encoder.encode(value).byteLength;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codePoint = value.charCodeAt(index);
    if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
      const nextCodePoint = value.charCodeAt(index + 1);
      if (nextCodePoint < 0xdc00 || nextCodePoint > 0xdfff) {
        return true;
      }
      index += 1;
    } else if (codePoint >= 0xdc00 && codePoint <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function base64UrlToBytes(value) {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error("invalid base64url");
  }
  const padded = `${value.replace(/-/g, "+").replace(/_/g, "/")}${"=".repeat((4 - (value.length % 4)) % 4)}`;
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function jsonResponse(payload, status = 200, additionalHeaders = {}) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, max-age=0",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000",
  });
  for (const [name, value] of Object.entries(additionalHeaders)) {
    headers.set(name, value);
  }
  return new Response(JSON.stringify(payload), { status, headers });
}

function appResponse(headOnly) {
  const nonce = pageNonce();
  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store, max-age=0",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": [
      "default-src 'self'",
      `script-src 'nonce-${nonce}'`,
      `style-src 'nonce-${nonce}'`,
      "connect-src 'self'",
      "img-src 'self' data:",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join("; "),
  });
  return new Response(headOnly ? null : APP_HTML.replace(/__NONCE__/gu, nonce), {
    status: 200,
    headers,
  });
}

function pageNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function insecureTransportResponse(request, url) {
  if (request.method === "GET" || request.method === "HEAD") {
    const secureUrl = new URL(url);
    secureUrl.protocol = "https:";
    return new Response(null, {
      status: 308,
      headers: { Location: secureUrl.toString(), "Cache-Control": "no-store, max-age=0" },
    });
  }
  return jsonResponse(
    { error: "此管理页仅允许通过 HTTPS 访问。" },
    426,
    { Upgrade: "TLS/1.2, HTTP/1.3" },
  );
}

function methodNotAllowed(allowedMethods) {
  return jsonResponse(
    { error: "不支持此请求方法。" },
    405,
    { Allow: allowedMethods.join(", ") },
  );
}

function notFoundResponse() {
  return jsonResponse({ error: "未找到请求的资源。" }, 404);
}

function errorResponse(error) {
  if (error instanceof HttpError) {
    return jsonResponse({ error: error.message }, error.status);
  }
  return jsonResponse({ error: "服务器处理请求失败。" }, 500);
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const APP_HTML = String.raw`<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light dark">
    <title>Cloudflare KV 管理</title>
    <style nonce="__NONCE__">
      :root {
        color-scheme: light dark;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f4f7fb;
        color: #152033;
      }
      * { box-sizing: border-box; }
      body { margin: 0; min-width: 320px; }
      button, input, textarea { font: inherit; }
      button { cursor: pointer; }
      button:disabled { cursor: wait; opacity: .6; }
      .hidden { display: none !important; }
      .shell { width: min(1400px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 40px; }
      .topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 24px; }
      h1, h2, p { margin: 0; }
      h1 { font-size: clamp(1.5rem, 3vw, 2rem); }
      h2 { font-size: 1.05rem; }
      .muted, .note { color: #5c6a82; font-size: .9rem; line-height: 1.5; }
      .panel { background: #fff; border: 1px solid #dfe5ef; border-radius: 14px; box-shadow: 0 8px 30px rgb(31 49 80 / .06); }
      .login { width: min(430px, 100%); margin: 10vh auto; padding: 28px; }
      .login h1 { margin-bottom: 8px; }
      .login .muted { margin-bottom: 24px; }
      .field { display: grid; gap: 7px; margin: 16px 0; font-weight: 600; }
      input, textarea { width: 100%; border: 1px solid #bec9da; border-radius: 9px; padding: 10px 12px; background: #fff; color: #152033; }
      input:focus, textarea:focus { outline: 3px solid rgb(49 130 246 / .22); border-color: #3182f6; }
      textarea { min-height: 380px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9rem; line-height: 1.5; }
      .button { border: 0; border-radius: 9px; padding: 10px 14px; background: #2563eb; color: #fff; font-weight: 700; }
      .button:hover:not(:disabled) { background: #1d4ed8; }
      .button.secondary { background: #e9eef7; color: #1e3555; }
      .button.secondary:hover:not(:disabled) { background: #dce5f4; }
      .button.danger { background: #b42318; }
      .workspace { display: grid; grid-template-columns: 280px minmax(270px, 360px) minmax(0, 1fr); gap: 16px; align-items: start; }
      .column { min-width: 0; overflow: hidden; }
      .column-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 17px 18px; border-bottom: 1px solid #e4e9f2; }
      .list { max-height: calc(100vh - 220px); min-height: 180px; overflow: auto; padding: 8px; }
      .list-button { display: grid; gap: 3px; width: 100%; border: 0; border-radius: 8px; padding: 10px; background: transparent; color: inherit; text-align: left; }
      .list-button:hover, .list-button.active { background: #eaf1ff; }
      .list-button strong, .list-button span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .list-button span { color: #64748b; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .76rem; }
      .empty { padding: 20px 12px; color: #67758b; font-size: .9rem; }
      .list-footer { padding: 10px; border-top: 1px solid #e4e9f2; }
      .list-footer .button { width: 100%; }
      .key-tools { display: grid; grid-template-columns: 1fr auto; gap: 8px; padding: 12px; border-bottom: 1px solid #e4e9f2; }
      .key-tools input { min-width: 0; }
      .editor { padding: 20px; }
      .editor-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .editor-meta { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 16px; }
      .tag { border-radius: 999px; padding: 4px 9px; background: #edf2f8; color: #45566f; font-size: .78rem; }
      .actions { display: flex; flex-wrap: wrap; gap: 9px; align-items: center; margin-top: 14px; }
      .status { min-height: 1.45em; margin-top: 14px; font-size: .9rem; line-height: 1.45; }
      .status.error { color: #b42318; }
      .status.success { color: #137333; }
      .status.info { color: #34567d; }
      .editor .note { margin-top: 14px; }
      @media (max-width: 950px) {
        .workspace { grid-template-columns: 1fr 1fr; }
        .editor-column { grid-column: 1 / -1; }
        .list { max-height: 260px; }
      }
      @media (max-width: 620px) {
        .shell { width: min(100% - 20px, 1400px); padding-top: 18px; }
        .workspace { grid-template-columns: 1fr; }
        .editor-column { grid-column: auto; }
        .topbar { align-items: flex-start; flex-direction: column; }
        .key-tools { grid-template-columns: 1fr; }
      }
      @media (prefers-color-scheme: dark) {
        :root { background: #111827; color: #e5edf9; }
        .panel { background: #182233; border-color: #293a54; box-shadow: none; }
        .muted, .note, .empty, .list-button span { color: #a9b7cb; }
        input, textarea { border-color: #43536c; background: #101827; color: #edf3ff; }
        .button.secondary { background: #2b3c57; color: #e4edfa; }
        .button.secondary:hover:not(:disabled) { background: #38506f; }
        .list-button:hover, .list-button.active { background: #203858; }
        .column-header, .key-tools, .list-footer { border-color: #293a54; }
        .tag { background: #2a3950; color: #c7d3e7; }
      }
    </style>
  </head>
  <body>
    <main class="shell">
      <section id="login-view" class="panel login" aria-labelledby="login-heading">
        <h1 id="login-heading">Cloudflare KV 管理</h1>
        <p class="muted">输入此管理页的登录密码。Cloudflare API Token 始终保留在服务器 Secret 中。</p>
        <form id="login-form">
          <label class="field" for="password">管理密码
            <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
          </label>
          <button id="login-button" class="button" type="submit">登录</button>
        </form>
        <p id="login-status" class="status" role="status" aria-live="polite"></p>
      </section>

      <section id="app-view" class="hidden" aria-label="KV 管理工作区">
        <header class="topbar">
          <div>
            <h1>Cloudflare KV 管理</h1>
            <p class="muted">浏览、读取、新建、修改和删除一个受限账号中的 UTF-8 文本值。</p>
          </div>
          <button id="logout-button" class="button secondary" type="button">退出登录</button>
        </header>

        <div class="workspace">
          <section class="panel column" aria-labelledby="namespace-heading">
            <div class="column-header">
              <h2 id="namespace-heading">KV 命名空间</h2>
              <button id="refresh-namespaces" class="button secondary" type="button">刷新</button>
            </div>
            <div id="namespace-list" class="list" aria-live="polite"></div>
            <div id="namespace-footer" class="list-footer hidden">
              <button id="more-namespaces" class="button secondary" type="button">加载更多</button>
            </div>
          </section>

          <section class="panel column" aria-labelledby="key-heading">
            <div class="column-header">
              <h2 id="key-heading">键</h2>
              <button id="new-key-button" class="button" type="button" disabled>新建键</button>
            </div>
            <form id="key-filter-form" class="key-tools">
              <input id="key-prefix" type="search" placeholder="按键前缀筛选" aria-label="键前缀">
              <button class="button secondary" type="submit">筛选</button>
            </form>
            <div id="key-list" class="list" aria-live="polite"></div>
            <div id="key-footer" class="list-footer hidden">
              <button id="more-keys" class="button secondary" type="button">加载更多</button>
            </div>
          </section>

          <section class="panel column editor-column" aria-labelledby="editor-heading">
            <div class="editor">
              <h2 id="editor-heading" class="editor-title">选择一个键开始编辑</h2>
              <div id="editor-meta" class="editor-meta hidden"></div>
              <label class="field" for="key-input">键
                <input id="key-input" type="text" autocomplete="off" disabled>
              </label>
              <label class="field" for="value-input">UTF-8 文本值
                <textarea id="value-input" spellcheck="false" disabled></textarea>
              </label>
              <div class="actions">
                <button id="save-button" class="button" type="button" disabled>保存</button>
                <button id="delete-button" class="button danger" type="button" disabled>删除</button>
              </div>
              <p id="app-status" class="status" role="status" aria-live="polite"></p>
              <p class="note">可新建、修改和删除键；现有键名不可直接改名。新建键默认无 metadata 且永不过期；创建前会检查同名键，但该检查与写入不是原子操作，并发创建仍可能由最后一次写入覆盖。修改已有键前会重新读取 metadata 和过期时间，并尽力写回。删除需输入完整键名确认，且不可恢复。KV 是最终一致的，新建或删除后列表可能暂时未反映。统一的 LF、CRLF 或 CR 换行会保留；混合换行的值若被修改，编辑器会拒绝保存以防止静默改写。二进制值和大于 1 MiB 的文本不会在此编辑器中打开。</p>
            </div>
          </section>
        </div>
      </section>
    </main>

    <script nonce="__NONCE__">
      (function () {
        "use strict";

        var state = {
          namespaces: [],
          namespacePage: 1,
          nextNamespacePage: null,
          selectedNamespace: null,
          keys: [],
          nextKeyCursor: null,
          selectedKey: null,
          editorMode: "idle",
          originalValue: "",
          originalEditorValue: "",
          lineEndingStyle: "lf",
          mutating: false,
          authenticated: false,
          authRequestVersion: 0,
          namespaceRequestVersion: 0,
          keyRequestVersion: 0,
          valueRequestVersion: 0,
          mutationRequestVersion: 0
        };

        var ui = {
          loginView: document.getElementById("login-view"),
          appView: document.getElementById("app-view"),
          loginForm: document.getElementById("login-form"),
          password: document.getElementById("password"),
          loginButton: document.getElementById("login-button"),
          loginStatus: document.getElementById("login-status"),
          logoutButton: document.getElementById("logout-button"),
          namespaceList: document.getElementById("namespace-list"),
          refreshNamespaces: document.getElementById("refresh-namespaces"),
          namespaceFooter: document.getElementById("namespace-footer"),
          moreNamespaces: document.getElementById("more-namespaces"),
          keyHeading: document.getElementById("key-heading"),
          newKeyButton: document.getElementById("new-key-button"),
          keyList: document.getElementById("key-list"),
          keyFilterForm: document.getElementById("key-filter-form"),
          keyPrefix: document.getElementById("key-prefix"),
          keyFooter: document.getElementById("key-footer"),
          moreKeys: document.getElementById("more-keys"),
          editorHeading: document.getElementById("editor-heading"),
          editorMeta: document.getElementById("editor-meta"),
          keyInput: document.getElementById("key-input"),
          valueInput: document.getElementById("value-input"),
          saveButton: document.getElementById("save-button"),
          deleteButton: document.getElementById("delete-button"),
          appStatus: document.getElementById("app-status")
        };

        function api(path, options) {
          var requestOptions = options || {};
          var headers = new Headers(requestOptions.headers || {});
          headers.set("Accept", "application/json");
          if (requestOptions.body !== undefined) {
            headers.set("Content-Type", "application/json");
          }
          return fetch(path, {
            method: requestOptions.method || "GET",
            headers: headers,
            body: requestOptions.body === undefined ? undefined : JSON.stringify(requestOptions.body),
            credentials: "same-origin"
          }).then(function (response) {
            return response.json().catch(function () {
              return {};
            }).then(function (body) {
              if (!response.ok) {
                var error = new Error(body.error || "请求失败。");
                error.status = response.status;
                throw error;
              }
              return body;
            });
          });
        }

        function setStatus(element, message, kind) {
          element.textContent = message || "";
          element.className = "status" + (kind ? " " + kind : "");
        }

        function isSelectedNamespace(namespaceId) {
          return state.selectedNamespace && state.selectedNamespace.id === namespaceId;
        }

        function invalidateSelectedNamespaceRequests() {
          state.keyRequestVersion += 1;
          state.valueRequestVersion += 1;
          invalidateMutations();
        }

        function invalidateMutations() {
          state.mutationRequestVersion += 1;
          state.mutating = false;
        }

        function clearWorkspace() {
          state.namespaceRequestVersion += 1;
          invalidateSelectedNamespaceRequests();
          state.namespaces = [];
          state.namespacePage = 1;
          state.nextNamespacePage = null;
          state.selectedNamespace = null;
          state.keys = [];
          state.nextKeyCursor = null;
          ui.keyPrefix.value = "";
          ui.keyHeading.textContent = "键";
          ui.refreshNamespaces.disabled = true;
          ui.moreNamespaces.disabled = true;
          ui.moreKeys.disabled = true;
          resetEditor();
          renderNamespaces();
          renderKeys();
          setStatus(ui.appStatus, "", "");
        }

        function showLogin(message) {
          state.authenticated = false;
          clearWorkspace();
          ui.appView.classList.add("hidden");
          ui.loginView.classList.remove("hidden");
          ui.loginButton.disabled = false;
          setStatus(ui.loginStatus, message || "", message ? "info" : "");
          ui.password.focus();
        }

        function showApp() {
          state.authenticated = true;
          clearWorkspace();
          ui.loginView.classList.add("hidden");
          ui.appView.classList.remove("hidden");
          setStatus(ui.loginStatus, "", "");
        }

        function expireSession(message) {
          state.authRequestVersion += 1;
          showLogin(message);
        }

        function createListButton(primary, secondary, active, onClick) {
          var button = document.createElement("button");
          var label = document.createElement("strong");
          var detail = document.createElement("span");
          button.type = "button";
          button.className = "list-button" + (active ? " active" : "");
          label.textContent = primary;
          detail.textContent = secondary;
          button.append(label, detail);
          button.addEventListener("click", onClick);
          return button;
        }

        function renderNamespaces() {
          ui.namespaceList.replaceChildren();
          if (state.namespaces.length === 0) {
            var empty = document.createElement("p");
            empty.className = "empty";
            empty.textContent = "没有可访问的 KV 命名空间。";
            ui.namespaceList.append(empty);
          } else {
            state.namespaces.forEach(function (namespace) {
              var namespaceButton = createListButton(
                namespace.title,
                namespace.id,
                state.selectedNamespace && state.selectedNamespace.id === namespace.id,
                function () { selectNamespace(namespace); }
              );
              namespaceButton.disabled = state.mutating;
              ui.namespaceList.append(namespaceButton);
            });
          }
          ui.namespaceFooter.classList.toggle("hidden", !state.nextNamespacePage);
        }

        function renderKeys() {
          ui.keyList.replaceChildren();
          if (!state.selectedNamespace) {
            var prompt = document.createElement("p");
            prompt.className = "empty";
            prompt.textContent = "先选择一个 KV 命名空间。";
            ui.keyList.append(prompt);
          } else if (state.keys.length === 0) {
            var empty = document.createElement("p");
            empty.className = "empty";
            empty.textContent = "没有匹配的键。";
            ui.keyList.append(empty);
          } else {
            state.keys.forEach(function (key) {
              var keyButton = createListButton(
                key.name,
                formatExpiration(key.expiration),
                state.selectedKey === key.name,
                function () { openKey(key); }
              );
              keyButton.disabled = state.mutating;
              ui.keyList.append(keyButton);
            });
          }
          ui.keyFooter.classList.toggle("hidden", !state.nextKeyCursor);
        }

        function formatExpiration(expiration) {
          if (!expiration) {
            return "永不过期";
          }
          return "过期：" + new Date(expiration * 1000).toLocaleString();
        }

        function resetEditor() {
          state.selectedKey = null;
          state.editorMode = "idle";
          state.originalValue = "";
          state.originalEditorValue = "";
          state.lineEndingStyle = "lf";
          ui.editorHeading.textContent = state.selectedNamespace ? "选择一个键开始编辑" : "选择一个命名空间开始编辑";
          ui.editorMeta.replaceChildren();
          ui.editorMeta.classList.add("hidden");
          ui.keyInput.value = "";
          ui.valueInput.value = "";
          updateEditorControls();
        }

        function updateEditorControls() {
          var editing = state.editorMode === "edit";
          var creating = state.editorMode === "create";
          var editorAvailable = !state.mutating && (editing || creating);
          ui.newKeyButton.disabled =
            !state.selectedNamespace || state.mutating || state.editorMode === "loading";
          setListButtonsDisabled(ui.namespaceList, state.mutating);
          setListButtonsDisabled(ui.keyList, state.mutating);
          ui.keyInput.disabled = !editorAvailable || !creating;
          ui.valueInput.disabled = !editorAvailable;
          ui.saveButton.disabled = !editorAvailable;
          ui.deleteButton.disabled = !editorAvailable || !editing || !state.selectedKey;
          ui.saveButton.textContent = creating ? "创建" : "保存";
        }

        function setListButtonsDisabled(list, disabled) {
          Array.prototype.forEach.call(list.children, function (child) {
            if (child.type === "button") {
              child.disabled = disabled;
            }
          });
        }

        function normalizeTextareaLineEndings(value) {
          return value.replace(/\r\n|\r/g, "\n");
        }

        function lineEndingStyle(value) {
          var hasLf = false;
          var hasCrLf = false;
          var hasCr = false;
          for (var index = 0; index < value.length; index += 1) {
            if (value.charAt(index) === "\r") {
              if (value.charAt(index + 1) === "\n") {
                hasCrLf = true;
                index += 1;
              } else {
                hasCr = true;
              }
            } else if (value.charAt(index) === "\n") {
              hasLf = true;
            }
          }
          if (Number(hasLf) + Number(hasCrLf) + Number(hasCr) > 1) {
            return "mixed";
          }
          if (hasCrLf) {
            return "crlf";
          }
          if (hasCr) {
            return "cr";
          }
          return "lf";
        }

        function rememberEditorValue(value) {
          state.originalValue = value;
          state.originalEditorValue = normalizeTextareaLineEndings(value);
          state.lineEndingStyle = lineEndingStyle(value);
        }

        function valueForSave() {
          var editorValue = ui.valueInput.value;
          if (editorValue === state.originalEditorValue) {
            return { unchanged: true };
          }
          if (state.lineEndingStyle === "mixed") {
            setStatus(
              ui.appStatus,
              "原值含混合换行。为避免静默改写，请使用可保留原始换行的专用工具修改。",
              "error"
            );
            return null;
          }
          if (state.lineEndingStyle === "crlf") {
            return { value: editorValue.replace(/\n/g, "\r\n") };
          }
          if (state.lineEndingStyle === "cr") {
            return { value: editorValue.replace(/\n/g, "\r") };
          }
          return { value: editorValue };
        }

        function setEditorMeta(expiration, hasMetadata) {
          ui.editorMeta.replaceChildren();
          var expirationTag = document.createElement("span");
          var metadataTag = document.createElement("span");
          expirationTag.className = "tag";
          metadataTag.className = "tag";
          expirationTag.textContent = formatExpiration(expiration);
          metadataTag.textContent = hasMetadata ? "包含 metadata（保存时保留）" : "无 metadata";
          ui.editorMeta.append(expirationTag, metadataTag);
          if (state.lineEndingStyle === "mixed") {
            var lineEndingTag = document.createElement("span");
            lineEndingTag.className = "tag";
            lineEndingTag.textContent = "混合换行：改动后将拒绝保存";
            ui.editorMeta.append(lineEndingTag);
          }
          ui.editorMeta.classList.remove("hidden");
        }

        function loadNamespaces(append) {
          var targetPage = append ? state.nextNamespacePage : 1;
          if (!targetPage) {
            return Promise.resolve();
          }
          var requestVersion = state.namespaceRequestVersion + 1;
          state.namespaceRequestVersion = requestVersion;
          ui.refreshNamespaces.disabled = true;
          ui.moreNamespaces.disabled = true;
          return api("/api/namespaces?page=" + encodeURIComponent(String(targetPage))).then(function (data) {
            if (requestVersion !== state.namespaceRequestVersion) {
              return;
            }
            state.namespaces = append ? state.namespaces.concat(data.items) : data.items;
            state.namespacePage = targetPage;
            state.nextNamespacePage = data.nextPage;
            renderNamespaces();
            if (!state.mutating) {
              setStatus(ui.appStatus, "", "");
            }
          }).catch(function (error) {
            if (requestVersion === state.namespaceRequestVersion) {
              handleAppError(error);
            }
          }).finally(function () {
            if (requestVersion !== state.namespaceRequestVersion) {
              return;
            }
            ui.refreshNamespaces.disabled = false;
            ui.moreNamespaces.disabled = false;
          });
        }

        function selectNamespace(namespace) {
          if (state.mutating) {
            return;
          }
          if (state.selectedNamespace && state.selectedNamespace.id === namespace.id) {
            return;
          }
          invalidateSelectedNamespaceRequests();
          state.selectedNamespace = namespace;
          state.keys = [];
          state.nextKeyCursor = null;
          ui.keyHeading.textContent = "键 · " + namespace.title;
          resetEditor();
          renderNamespaces();
          renderKeys();
          loadKeys(false);
        }

        function loadKeys(append) {
          if (!state.selectedNamespace) {
            return Promise.resolve();
          }
          var cursor = append ? state.nextKeyCursor : null;
          if (append && !cursor) {
            return Promise.resolve();
          }
          var namespaceId = state.selectedNamespace.id;
          var requestVersion = state.keyRequestVersion + 1;
          state.keyRequestVersion = requestVersion;
          var params = new URLSearchParams({ namespaceId: state.selectedNamespace.id });
          var prefix = ui.keyPrefix.value;
          if (prefix) {
            params.set("prefix", prefix);
          }
          if (cursor) {
            params.set("cursor", cursor);
          }
          ui.moreKeys.disabled = true;
          return api("/api/keys?" + params.toString()).then(function (data) {
            if (requestVersion !== state.keyRequestVersion || !isSelectedNamespace(namespaceId)) {
              return;
            }
            state.keys = append ? state.keys.concat(data.items) : data.items;
            state.nextKeyCursor = data.cursor;
            renderKeys();
          }).catch(function (error) {
            if (requestVersion === state.keyRequestVersion && isSelectedNamespace(namespaceId)) {
              handleAppError(error);
            }
          }).finally(function () {
            if (requestVersion !== state.keyRequestVersion || !isSelectedNamespace(namespaceId)) {
              return;
            }
            ui.moreKeys.disabled = false;
          });
        }

        function startCreateKey() {
          if (!state.selectedNamespace || state.mutating) {
            return;
          }
          state.valueRequestVersion += 1;
          invalidateMutations();
          resetEditor();
          state.editorMode = "create";
          ui.editorHeading.textContent = "新建键";
          setEditorMeta(null, false);
          updateEditorControls();
          ui.keyInput.focus();
          setStatus(ui.appStatus, "新建键默认无 metadata 且永不过期。", "info");
          renderKeys();
        }

        function openKey(key) {
          if (!state.selectedNamespace || state.mutating) {
            return;
          }
          var namespaceId = state.selectedNamespace.id;
          var keyName = key.name;
          var requestVersion = state.valueRequestVersion + 1;
          state.valueRequestVersion = requestVersion;
          invalidateMutations();
          resetEditor();
          state.editorMode = "loading";
          ui.editorHeading.textContent = "正在读取键值…";
          updateEditorControls();
          renderKeys();
          setStatus(ui.appStatus, "正在读取键值…", "info");
          var params = new URLSearchParams({
            namespaceId: namespaceId,
            key: keyName
          });
          api("/api/value?" + params.toString()).then(function (data) {
            if (
              requestVersion !== state.valueRequestVersion ||
              !isSelectedNamespace(namespaceId)
            ) {
              return;
            }
            if (typeof data.value !== "string") {
              throw new Error("服务器返回了无效的文本值。");
            }
            state.selectedKey = keyName;
            state.editorMode = "edit";
            ui.editorHeading.textContent = keyName;
            ui.keyInput.value = keyName;
            rememberEditorValue(data.value);
            ui.valueInput.value = state.originalEditorValue;
            setEditorMeta(data.expiration, data.hasMetadata);
            updateEditorControls();
            setStatus(ui.appStatus, "", "");
            renderKeys();
          }).catch(function (error) {
            if (
              requestVersion !== state.valueRequestVersion ||
              !isSelectedNamespace(namespaceId)
            ) {
              return;
            }
            resetEditor();
            handleAppError(error);
          });
        }

        function saveCurrentValue() {
          var creating = state.editorMode === "create";
          var editing = state.editorMode === "edit";
          if (!state.selectedNamespace || (!creating && !editing) || state.mutating) {
            return;
          }
          var namespaceId = state.selectedNamespace.id;
          var key = creating ? ui.keyInput.value : state.selectedKey;
          if (!key) {
            setStatus(ui.appStatus, "请输入键名。", "error");
            ui.keyInput.focus();
            return;
          }

          var value;
          if (creating) {
            // An empty string is a valid value for a newly created key.
            value = ui.valueInput.value;
          } else {
            var preparedValue = valueForSave();
            if (!preparedValue) {
              return;
            }
            if (preparedValue.unchanged) {
              setStatus(ui.appStatus, "未检测到修改，未执行保存。", "info");
              return;
            }
            value = preparedValue.value;
          }

          var requestVersion = state.mutationRequestVersion + 1;
          state.mutationRequestVersion = requestVersion;
          state.mutating = true;
          updateEditorControls();
          setStatus(ui.appStatus, creating ? "正在创建…" : "正在保存…", "info");
          api("/api/value", {
            method: creating ? "POST" : "PUT",
            body: {
              namespaceId: namespaceId,
              key: key,
              value: value
            }
          }).then(function () {
            if (
              requestVersion !== state.mutationRequestVersion ||
              !isSelectedNamespace(namespaceId)
            ) {
              return;
            }
            state.selectedKey = key;
            state.editorMode = "edit";
            rememberEditorValue(value);
            ui.keyInput.value = key;
            ui.editorHeading.textContent = key;
            if (creating) {
              setEditorMeta(null, false);
              setStatus(ui.appStatus, "已创建。KV 最终一致，键列表可能暂时未反映。", "success");
            } else {
              setStatus(ui.appStatus, "已保存。", "success");
            }
            renderKeys();
            loadKeys(false);
          }).catch(function (error) {
            if (
              requestVersion === state.mutationRequestVersion &&
              isSelectedNamespace(namespaceId)
            ) {
              handleAppError(error);
            }
          }).finally(function () {
            if (
              requestVersion !== state.mutationRequestVersion ||
              !isSelectedNamespace(namespaceId)
            ) {
              return;
            }
            state.mutating = false;
            updateEditorControls();
          });
        }

        function deleteCurrentValue() {
          if (
            !state.selectedNamespace ||
            state.editorMode !== "edit" ||
            !state.selectedKey ||
            state.mutating
          ) {
            return;
          }
          var namespaceId = state.selectedNamespace.id;
          var key = state.selectedKey;
          var confirmation = prompt(
            "删除后无法恢复。请输入下面的完整键名以确认删除：\n" + key
          );
          if (confirmation === null) {
            return;
          }
          if (confirmation !== key) {
            setStatus(ui.appStatus, "输入的键名不匹配，未执行删除。", "error");
            return;
          }

          var requestVersion = state.mutationRequestVersion + 1;
          state.mutationRequestVersion = requestVersion;
          state.mutating = true;
          updateEditorControls();
          setStatus(ui.appStatus, "正在删除…", "info");
          api("/api/value", {
            method: "DELETE",
            body: {
              namespaceId: namespaceId,
              key: key,
              confirmation: confirmation
            }
          }).then(function () {
            if (
              requestVersion !== state.mutationRequestVersion ||
              !isSelectedNamespace(namespaceId)
            ) {
              return;
            }
            resetEditor();
            renderKeys();
            setStatus(ui.appStatus, "已删除。KV 最终一致，键列表可能暂时未反映。", "success");
            loadKeys(false);
          }).catch(function (error) {
            if (
              requestVersion === state.mutationRequestVersion &&
              isSelectedNamespace(namespaceId)
            ) {
              handleAppError(error);
            }
          }).finally(function () {
            if (
              requestVersion !== state.mutationRequestVersion ||
              !isSelectedNamespace(namespaceId)
            ) {
              return;
            }
            state.mutating = false;
            updateEditorControls();
          });
        }

        function handleAppError(error) {
          if (error && error.status === 401) {
            expireSession("登录已过期，请重新登录。");
            return;
          }
          setStatus(ui.appStatus, error && error.message ? error.message : "请求失败。", "error");
        }

        ui.loginForm.addEventListener("submit", function (event) {
          event.preventDefault();
          var authRequestVersion = state.authRequestVersion + 1;
          state.authRequestVersion = authRequestVersion;
          ui.loginButton.disabled = true;
          setStatus(ui.loginStatus, "正在登录…", "info");
          api("/api/session", {
            method: "POST",
            body: { password: ui.password.value }
          }).then(function () {
            if (authRequestVersion !== state.authRequestVersion) {
              return null;
            }
            ui.password.value = "";
            showApp();
            return loadNamespaces(false);
          }).catch(function (error) {
            if (authRequestVersion !== state.authRequestVersion) {
              return;
            }
            setStatus(ui.loginStatus, error && error.message ? error.message : "登录失败。", "error");
          }).finally(function () {
            if (authRequestVersion !== state.authRequestVersion) {
              return;
            }
            ui.loginButton.disabled = false;
          });
        });

        ui.logoutButton.addEventListener("click", function () {
          var authRequestVersion = state.authRequestVersion + 1;
          state.authRequestVersion = authRequestVersion;
          ui.logoutButton.disabled = true;
          clearWorkspace();
          api("/api/session", { method: "DELETE" }).catch(function () {
            return null;
          }).finally(function () {
            if (authRequestVersion !== state.authRequestVersion) {
              return;
            }
            ui.logoutButton.disabled = false;
            showLogin("已退出登录。");
          });
        });

        ui.refreshNamespaces.addEventListener("click", function () { loadNamespaces(false); });
        ui.moreNamespaces.addEventListener("click", function () { loadNamespaces(true); });
        ui.newKeyButton.addEventListener("click", startCreateKey);
        ui.moreKeys.addEventListener("click", function () { loadKeys(true); });
        ui.saveButton.addEventListener("click", saveCurrentValue);
        ui.deleteButton.addEventListener("click", deleteCurrentValue);
        ui.keyFilterForm.addEventListener("submit", function (event) {
          event.preventDefault();
          loadKeys(false);
        });

        (function checkInitialSession() {
          var authRequestVersion = state.authRequestVersion + 1;
          state.authRequestVersion = authRequestVersion;
          api("/api/session").then(function (data) {
            if (authRequestVersion !== state.authRequestVersion) {
              return null;
            }
            if (data.authenticated) {
              showApp();
              return loadNamespaces(false);
            }
            showLogin();
            return null;
          }).catch(function () {
            if (authRequestVersion === state.authRequestVersion) {
              showLogin("无法检查登录状态，请重试。");
            }
          });
        }());
      }());
    </script>
  </body>
</html>`;

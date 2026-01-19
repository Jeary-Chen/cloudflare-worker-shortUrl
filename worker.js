async function jwtSign(payload, secret) {
  const encoder = new TextEncoder();
  const header = JSON.stringify({ alg: "HS256", typ: "JWT" });
  const encodedHeader = btoa(header).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const data = encoder.encode(encodedHeader + "." + encodedPayload);
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, data);
  const encodedSignature = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(signature))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return encodedHeader + "." + encodedPayload + "." + encodedSignature;
}

async function jwtVerify(token, secret) {
  try {
    const encoder = new TextEncoder();
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const encodedHeader = parts[0];
    const encodedPayload = parts[1];
    const encodedSignature = parts[2];
    const data = encoder.encode(encodedHeader + "." + encodedPayload);
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const rawSignature = encodedSignature.replace(/-/g, "+").replace(/_/g, "/");
    const signatureBytes = Uint8Array.from(atob(rawSignature), function (c) {
      return c.charCodeAt(0);
    });
    const isValid = await crypto.subtle.verify("HMAC", key, signatureBytes, data);
    if (!isValid) return null;
    const rawPayload = encodedPayload.replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(rawPayload));
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function jsonResponse(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "Content-Type": "application/json" }
  });
}

function isValidUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch (e) {
    return false;
  }
}

function getMaxShortCodeLength(env) {
  const n = parseInt(env.MAX_SHORTCODE_LENGTH || "16", 10);
  if (!n || n < 2) return 16;
  if (n > 64) return 64;
  return n;
}

function getDefaultExpireDays(env) {
  const n = parseInt(env.DEFAULT_EXPIRE_DAYS || "90", 10);
  if (isNaN(n)) return 90;
  if (n < 0) return 0;
  return n;
}

function isFrontendExpireSelectEnabled(env) {
  const v = String(env.FRONTEND_EXPIRE_SELECT_ENABLED || "true").toLowerCase();
  return v === "true" || v === "1" || v === "yes";
}

function getMaxExpireDays(env) {
  const n = parseInt(env.MAX_EXPIRE_DAYS || "3650", 10);
  if (isNaN(n) || n < 0) return 3650;
  return n;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, "");
    if (!env.URL_KV) {
      return new Response("Missing KV binding URL_KV", { status: 500 });
    }
    if (path === "") {
      return renderHome(env);
    }
    if (path === "/admin") {
      return handleAdmin(request, env);
    }
    if (path === "/api/shorten") {
      return handleShortenApi(request, env);
    }
    if (path === "/api/create") {
      return handleCreateApi(request, env);
    }
    if (path === "/create") {
      return handleCreateHome(request, env);
    }
    const shortCode = path.slice(1);
    return handleRedirect(request, env, shortCode);
  }
};

async function handleRedirect(request, env, shortCode) {
  if (!shortCode) {
    return new Response("Not found", { status: 404 });
  }
  const raw = await env.URL_KV.get(shortCode);
  if (!raw) {
    return new Response("短链接不存在或已过期", {
      status: 404,
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
  const data = JSON.parse(raw);
  const url = data.url;
  const expireAt = data.expireAt;
  const password = data.password;
  const redirectType = data.redirectType || 302;
  if (expireAt && new Date(expireAt).getTime() < Date.now()) {
    await cleanupLink(env, shortCode);
    return new Response("短链接已过期", {
      status: 410,
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
  const currentUrl = new URL(request.url);
  const pwdParam = currentUrl.searchParams.get("pwd") || "";
  if (password && pwdParam !== password) {
    return renderPasswordAuth(shortCode);
  }
  const logKey = "log_" + shortCode + "_" + Date.now();
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const ua = request.headers.get("User-Agent") || "";
  const logData = {
    ip: ip,
    userAgent: ua,
    time: new Date().toISOString()
  };
  await env.URL_KV.put(logKey, JSON.stringify(logData), {
    expirationTtl: 365 * 24 * 60 * 60
  });
  const statsKey = "stats_" + shortCode;
  const currentStats = (await env.URL_KV.get(statsKey)) || "0";
  const count = parseInt(currentStats, 10) || 0;
  await env.URL_KV.put(statsKey, String(count + 1));
  return renderJumpPage(url, shortCode, redirectType, env);
}

async function cleanupLink(env, shortCode) {
  const list = await env.URL_KV.list({ prefix: "log_" + shortCode + "_" });
  const deletions = [];
  for (const k of list.keys) {
    deletions.push(env.URL_KV.delete(k.name));
  }
  deletions.push(env.URL_KV.delete(shortCode));
  deletions.push(env.URL_KV.delete("stats_" + shortCode));
  await Promise.all(deletions);
}

async function handleAdmin(request, env) {
  if (!env.JWT_SECRET || !env.ADMIN_PASSWORD) {
    return new Response("缺少 JWT_SECRET 或 ADMIN_PASSWORD", {
      status: 500,
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
  const url = new URL(request.url);
  if (request.method === "GET") {
    const token = url.searchParams.get("token") || "";
    if (!token) {
      return renderLogin(env);
    }
    const payload = await jwtVerify(token, env.JWT_SECRET);
    if (!payload) {
      return renderLogin(env);
    }
    const stats = await getTotalStats(env);
    const links = await getAllLinks(env);
    return renderAdminUI(links, stats, token, env);
  }
  if (request.method === "POST") {
    const body = await request.json().catch(function () {
      return null;
    });
    if (!body || !body.action) {
      return new Response("无效请求", { status: 400 });
    }
    if (body.action === "login") {
      if (body.password !== env.ADMIN_PASSWORD) {
        return new Response("密码错误", { status: 401 });
      }
      const token = await jwtSign(
        {
          username: env.ADMIN_USERNAME || "admin",
          exp: Math.floor(Date.now() / 1000) + 86400
        },
        env.JWT_SECRET
      );
      return jsonResponse({ token: token });
    }
    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token) {
      return new Response("未授权", { status: 401 });
    }
    const payload = await jwtVerify(token, env.JWT_SECRET);
    if (!payload) {
      return new Response("未授权", { status: 401 });
    }
    if (body.action === "add") {
      return addLink(env, body);
    }
    if (body.action === "edit") {
      return editLink(env, body);
    }
    if (body.action === "addApiKey") {
      const key = (body.key || "").trim();
      if (!/^[A-Za-z0-9]{2,32}$/.test(key)) {
        return new Response("API Key 不合法", { status: 400 });
      }
      await env.URL_KV.put("api_key_" + key, "1");
      return new Response("OK");
    }
    if (body.action === "deleteApiKey") {
      const key = (body.key || "").trim();
      if (!key) {
        return new Response("缺少 key", { status: 400 });
      }
      await env.URL_KV.delete("api_key_" + key);
      return new Response("OK");
    }
    if (body.action === "listApiKeys") {
      const list = await env.URL_KV.list({ prefix: "api_key_" });
      const keys = [];
      for (const k of list.keys) {
        keys.push(k.name.slice("api_key_".length));
      }
      return jsonResponse(keys);
    }
    if (body.action === "delete") {
      return deleteLink(env, body.key);
    }
    if (body.action === "getLogs") {
      return getLinkLogs(env, body.key);
    }
    if (body.action === "batchDelete") {
      return batchDelete(env, body.keys || []);
    }
    if (body.action === "batchImport") {
      return batchImport(env, body.data || "[]");
    }
    if (body.action === "list") {
      const links = await getAllLinks(env);
      const stats = await getTotalStats(env);
      return jsonResponse({ links: links, stats: stats });
    }
    return new Response("无效操作", { status: 400 });
  }
  return new Response("Method Not Allowed", { status: 405 });
}

async function addLink(env, data) {
  const shortCode = (data.shortCode || "").trim();
  const url = (data.url || "").trim();
  let expireDays = parseInt(data.expireDays, 10);
  if (isNaN(expireDays)) expireDays = 0;
  const redirectType = parseInt(data.redirectType, 10) || 302;
  const password = (data.password || "").trim();
  if (!shortCode || !url) {
    return new Response("短码和URL不能为空", { status: 400 });
  }
  const maxLen = getMaxShortCodeLength(env);
  const re = new RegExp("^[A-Za-z0-9]{2," + maxLen + "}$");
  if (!re.test(shortCode)) {
    return new Response("短码格式不合法，长度最大为 " + maxLen, { status: 400 });
  }
  if (!isValidUrl(url)) {
    return new Response("URL格式无效", { status: 400 });
  }
  if (await env.URL_KV.get(shortCode)) {
    return new Response("短码已存在", { status: 409 });
  }
  if (String(data.source || "").toLowerCase() === "home" && !isFrontendExpireSelectEnabled(env)) {
    expireDays = getDefaultExpireDays(env);
  }
  const maxExpire = getMaxExpireDays(env);
  if (expireDays > maxExpire) {
    expireDays = maxExpire;
  }
  let expireAt = null;
  if (expireDays > 0) {
    expireAt = new Date(Date.now() + expireDays * 24 * 60 * 60 * 1000).toISOString();
  }
  const payload = {
    url: url,
    expireAt: expireAt,
    password: password,
    redirectType: redirectType
  };
  await env.URL_KV.put(shortCode, JSON.stringify(payload));
  await env.URL_KV.put("stats_" + shortCode, "0");
  return new Response("添加成功");
}

async function editLink(env, data) {
  const key = (data.key || "").trim();
  const url = (data.url || "").trim();
  let expireDays = parseInt(data.expireDays, 10);
  if (isNaN(expireDays)) expireDays = 0;
  const redirectType = parseInt(data.redirectType, 10) || 302;
  const password = (data.password || "").trim();
  const raw = await env.URL_KV.get(key);
  if (!raw) {
    return new Response("短链接不存在", { status: 404 });
  }
  if (!isValidUrl(url)) {
    return new Response("URL格式无效", { status: 400 });
  }
  const maxExpire = getMaxExpireDays(env);
  if (expireDays > maxExpire) {
    expireDays = maxExpire;
  }
  let expireAt = null;
  if (expireDays > 0) {
    expireAt = new Date(Date.now() + expireDays * 24 * 60 * 60 * 1000).toISOString();
  }
  const payload = {
    url: url,
    expireAt: expireAt,
    password: password,
    redirectType: redirectType
  };
  await env.URL_KV.put(key, JSON.stringify(payload));
  return new Response("修改成功");
}

async function deleteLink(env, key) {
  if (!key) {
    return new Response("缺少短码", { status: 400 });
  }
  await cleanupLink(env, key);
  return new Response("删除成功");
}

async function batchDelete(env, keys) {
  if (!Array.isArray(keys)) {
    return new Response("keys 必须是数组", { status: 400 });
  }
  let success = 0;
  for (const k of keys) {
    if (!k) continue;
    await cleanupLink(env, k);
    success += 1;
  }
  return jsonResponse({ success: success });
}

async function batchImport(env, data) {
  try {
    const list = JSON.parse(data);
    if (!Array.isArray(list)) {
      return new Response("数据格式错误", { status: 400 });
    }
    let success = 0;
    let fail = 0;
    const maxLen = getMaxShortCodeLength(env);
    const re = new RegExp("^[A-Za-z0-9]{2," + maxLen + "}$");
    const maxExpire = getMaxExpireDays(env);
    for (const item of list) {
      const shortCode = (item.shortCode || "").trim();
      const url = (item.url || "").trim();
      let expireDays = item.expireDays ? parseInt(item.expireDays, 10) : 0;
      if (isNaN(expireDays) || expireDays < 0) expireDays = 0;
      if (expireDays > maxExpire) expireDays = maxExpire;
      const password = (item.password || "").trim();
      const redirectType = item.redirectType === 301 ? 301 : 302;
      if (!shortCode || !url || !re.test(shortCode) || !isValidUrl(url)) {
        fail += 1;
        continue;
      }
      if (await env.URL_KV.get(shortCode)) {
        fail += 1;
        continue;
      }
      let expireAt = null;
      if (expireDays > 0) {
        expireAt = new Date(Date.now() + expireDays * 24 * 60 * 60 * 1000).toISOString();
      }
      const payload = {
        url: url,
        expireAt: expireAt,
        password: password,
        redirectType: redirectType
      };
      await env.URL_KV.put(shortCode, JSON.stringify(payload));
      await env.URL_KV.put("stats_" + shortCode, "0");
      success += 1;
    }
    return jsonResponse({ success: success, fail: fail });
  } catch (e) {
    return new Response("导入失败", { status: 500 });
  }
}

async function getLinkLogs(env, key) {
  if (!key) {
    return new Response("缺少短码", { status: 400 });
  }
  const list = await env.URL_KV.list({ prefix: "log_" + key + "_" });
  const logs = [];
  for (const k of list.keys) {
    const raw = await env.URL_KV.get(k.name);
    if (!raw) continue;
    const item = JSON.parse(raw);
    logs.push(item);
  }
  logs.sort(function (a, b) {
    return new Date(b.time).getTime() - new Date(a.time).getTime();
  });
  return jsonResponse(logs);
}

async function getAllLinks(env) {
  const list = await env.URL_KV.list({ prefix: "" });
  const result = [];
  for (const k of list.keys) {
    const name = k.name;
    if (name.indexOf("log_") === 0) continue;
    if (name.indexOf("stats_") === 0) continue;
    const raw = await env.URL_KV.get(name);
    if (!raw) continue;
    const data = JSON.parse(raw);
    const statsRaw = (await env.URL_KV.get("stats_" + name)) || "0";
    const stats = parseInt(statsRaw, 10) || 0;
    result.push({
      shortCode: name,
      url: data.url,
      expireAt: data.expireAt,
      password: data.password,
      redirectType: data.redirectType,
      stats: stats
    });
  }
  return result;
}

async function getTotalStats(env) {
  const links = await getAllLinks(env);
  let totalViews = 0;
  let active = 0;
  for (const item of links) {
    totalViews += item.stats || 0;
    if (!item.expireAt || new Date(item.expireAt).getTime() >= Date.now()) {
      active += 1;
    }
  }
  return {
    totalLinks: links.length,
    totalViews: totalViews,
    activeLinks: active
  };
}

async function handleShortenApi(request, env) {
  const url = new URL(request.url);
  const key = url.searchParams.get("key") || "";
  if (!key) {
    return new Response("缺少短码参数", { status: 400 });
  }
  const raw = await env.URL_KV.get(key);
  if (!raw) {
    return new Response("短链接不存在", { status: 404 });
  }
  return new Response(raw, {
    headers: { "Content-Type": "application/json" }
  });
}

function renderPasswordAuth(key) {
  const html =
    "<!DOCTYPE html>" +
    '<html lang="zh-CN">' +
    "<head>" +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    "<title>需要密码验证</title>" +
    '<script src="https://cdn.tailwindcss.com"></script>' +
    "<style>input[type=text],input[type=password],input[type=url],input[type=number],select{padding:.5rem .75rem;border:1px solid #e5e7eb;border-radius:.5rem;font-size:.875rem;outline:none}input:focus,select:focus{box-shadow:0 0 0 2px #93c5fd;border-color:#3b82f6}button{padding:.5rem .75rem;border-radius:.5rem;font-size:.875rem;border:1px solid transparent}button.primary{background:#3b82f6;color:#fff}button.primary:hover{background:#2563eb}button.danger{border-color:#ef4444;color:#ef4444;background:transparent}button.danger:hover{background:#fee2e2}button.outline{border-color:#e5e7eb;background:#fff;color:#111827}button.outline:hover{background:#f9fafb}</style>" +
    "</head>" +
    '<body class="min-h-screen bg-gray-50 flex items-center justify-center p-4">' +
    '<div class="w-full max-w-md bg-white rounded-xl p-8 shadow">' +
    '<div class="text-center mb-6">' +
    "" +
    '<h2 class="text-xl font-semibold text-gray-900">访问需要密码验证</h2>' +
    '<p class="text-gray-500 mt-2">该短链接受密码保护，请输入访问密码</p>' +
    "</div>" +
    '<form id="passwordForm" class="space-y-4">' +
    '<div>' +
    '<label class="block text-sm font-medium text-gray-700 mb-1">访问密码</label>' +
    '<div class="relative">' +
    '<input type="password" id="pwdInput" class="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none" placeholder="输入访问密码">' +
    "</div>" +
    "</div>" +
    '<button type="submit" class="w-full primary">验证并访问</button>' +
    "</form>" +
    "</div>" +
    "<script>" +
    "document.getElementById('passwordForm').addEventListener('submit',function(e){e.preventDefault();var pwd=document.getElementById('pwdInput').value;var u=new URL(window.location.href);u.searchParams.set('pwd',pwd);window.location.href=u.toString();});" +
    "</script>" +
    "</body>" +
    "</html>";
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function genRandomShortCode(env, len) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

async function generateUniqueShortCode(env, preferredLen) {
  const maxLen = getMaxShortCodeLength(env);
  let len = Math.min(preferredLen || 8, maxLen);
  for (let i = 0; i < 10; i++) {
    const c = genRandomShortCode(env, len);
    if (!(await env.URL_KV.get(c))) {
      return c;
    }
  }
  while (len < maxLen) {
    len += 1;
    const c2 = genRandomShortCode(env, len);
    if (!(await env.URL_KV.get(c2))) {
      return c2;
    }
  }
  return genRandomShortCode(env, len);
}

async function handleCreateApi(request, env) {
  const u = new URL(request.url);
  if (request.method !== "GET" && request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  let params = null;
  if (request.method === "GET") {
    params = {
      apiKey: (u.searchParams.get("key") || "").trim(),
      shortCode: (u.searchParams.get("code") || "").trim(),
      url: (u.searchParams.get("url") || "").trim(),
      expireDays: u.searchParams.get("expireDays"),
      redirectType: u.searchParams.get("redirectType"),
      password: u.searchParams.get("password")
    };
  } else {
    params = await request.json().catch(function () {
      return null;
    });
    if (!params) {
      return new Response("无效请求", { status: 400 });
    }
  }
  const apiKey = (params.apiKey || params.key || "").trim();
  if (!apiKey) {
    return new Response("缺少 API key", { status: 403 });
  }
  const allow = await env.URL_KV.get("api_key_" + apiKey);
  if (!allow) {
    return new Response("未授权的 API key", { status: 403 });
  }
  let shortCode = (params.shortCode || params.code || "").trim();
  const targetUrl = (params.url || "").trim();
  let expireDays = parseInt(params.expireDays, 10);
  if (isNaN(expireDays)) expireDays = getDefaultExpireDays(env);
  let redirectType = parseInt(params.redirectType, 10) || 302;
  const password = (params.password || "").trim();
  if (!targetUrl) {
    return new Response("缺少 URL", { status: 400 });
  }
  if (!isValidUrl(targetUrl)) {
    return new Response("URL格式无效", { status: 400 });
  }
  const maxLen = getMaxShortCodeLength(env);
  const re = new RegExp("^[A-Za-z0-9]{2," + maxLen + "}$");
  if (!shortCode) {
    shortCode = await generateUniqueShortCode(env, 8);
  } else {
    if (!re.test(shortCode)) {
      return new Response("短码格式不合法，长度最大为 " + maxLen, { status: 400 });
    }
    if (await env.URL_KV.get(shortCode)) {
      return new Response("短码已存在", { status: 409 });
    }
  }
  const maxExpire = getMaxExpireDays(env);
  if (expireDays > maxExpire) {
    expireDays = maxExpire;
  }
  let expireAt = null;
  if (expireDays > 0) {
    expireAt = new Date(Date.now() + expireDays * 24 * 60 * 60 * 1000).toISOString();
  }
  const payload = {
    url: targetUrl,
    expireAt: expireAt,
    password: password,
    redirectType: redirectType
  };
  await env.URL_KV.put(shortCode, JSON.stringify(payload));
  await env.URL_KV.put("stats_" + shortCode, "0");
  const origin = u.origin;
  return jsonResponse({
    shortCode: shortCode,
    shortUrl: origin + "/" + shortCode,
    expireAt: expireAt || null
  });
}

async function handleCreateHome(request, env) {
  const u = new URL(request.url);
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  const params = await request.json().catch(function () {
    return null;
  });
  if (!params) {
    return new Response("无效请求", { status: 400 });
  }
  let shortCode = (params.shortCode || params.code || "").trim();
  const targetUrl = (params.url || "").trim();
  let expireDays = parseInt(params.expireDays, 10);
  if (isNaN(expireDays)) expireDays = getDefaultExpireDays(env);
  let redirectType = parseInt(params.redirectType, 10) || 302;
  const password = (params.password || "").trim();
  if (!targetUrl) {
    return new Response("缺少 URL", { status: 400 });
  }
  if (!isValidUrl(targetUrl)) {
    return new Response("URL格式无效", { status: 400 });
  }
  const maxLen = getMaxShortCodeLength(env);
  const re = new RegExp("^[A-Za-z0-9]{2," + maxLen + "}$");
  if (!shortCode) {
    shortCode = await generateUniqueShortCode(env, 8);
  } else {
    if (!re.test(shortCode)) {
      return new Response("短码格式不合法，长度最大为 " + maxLen, { status: 400 });
    }
    if (await env.URL_KV.get(shortCode)) {
      return new Response("短码已存在", { status: 409 });
    }
  }
  if (!isFrontendExpireSelectEnabled(env)) {
    expireDays = getDefaultExpireDays(env);
  }
  const maxExpire = getMaxExpireDays(env);
  if (expireDays > maxExpire) {
    expireDays = maxExpire;
  }
  let expireAt = null;
  if (expireDays > 0) {
    expireAt = new Date(Date.now() + expireDays * 24 * 60 * 60 * 1000).toISOString();
  }
  const payload = {
    url: targetUrl,
    expireAt: expireAt,
    password: password,
    redirectType: redirectType
  };
  await env.URL_KV.put(shortCode, JSON.stringify(payload));
  await env.URL_KV.put("stats_" + shortCode, "0");
  const origin = u.origin;
  return jsonResponse({
    shortCode: shortCode,
    shortUrl: origin + "/" + shortCode,
    expireAt: expireAt || null
  });
}

function renderJumpPage(targetUrl, shortCode, redirectType, env) {
  const tpl = env.REDIRECT_HTML_TEMPLATE || "";
  if (tpl && tpl.indexOf("<") >= 0) {
    const html = tpl
      .replace(/\{\{URL\}\}/g, targetUrl)
      .replace(/\{\{CODE\}\}/g, shortCode)
      .replace(/\{\{TYPE\}\}/g, String(redirectType));
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  const html =
    "<!DOCTYPE html>" +
    '<html lang="zh-CN">' +
    "<head>" +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    "<title>正在跳转</title>" +
    "<style>" +
    "body{min-height:100vh;background:#f9fafb;display:flex;align-items:center;justify-content:center;padding:1rem;font-family:sans-serif;color:#111827;}" +
    ".container{width:100%;max-width:28rem;background:#fff;border-radius:0.75rem;padding:2rem;box-shadow:0 1px 3px 0 rgba(0,0,0,0.1);}" +
    ".icon{width:4rem;height:4rem;border-radius:50%;background:#eff6ff;display:flex;align-items:center;justify-content:center;color:#3b82f6;font-size:1.5rem;margin:0 auto 1.5rem;}" +
    ".title{font-size:1.25rem;font-weight:600;text-align:center;margin-bottom:0.5rem;}" +
    ".desc{font-size:0.875rem;color:#6b7280;text-align:center;margin-bottom:1.5rem;}" +
    ".url{font-size:0.75rem;word-break:break-all;background:#f9fafb;border:1px solid #e5e7eb;border-radius:0.375rem;padding:0.75rem;margin-bottom:1.5rem;}" +
    ".countdown{font-size:0.875rem;color:#6b7280;text-align:center;}" +
    "</style>" +
    "</head>" +
    "<body>" +
    '<div class="container">' +
    '<div class="icon">↗</div>' +
    '<h2 class="title">正在跳转</h2>' +
    '<p class="desc">短码 ' + shortCode + " 指向的目标地址</p>" +
    '<div class="url">' + targetUrl + "</div>" +
    '<div class="countdown"><span id="countdown">3 秒后自动跳转</span></div>' +
    "</div>" +
    "<script>" +
    "var u='" + targetUrl + "';" +
    "var c=3;var t=setInterval(function(){c--;document.getElementById('countdown').textContent=c+' 秒后自动跳转';if(c<=0){clearInterval(t);window.location.replace(u);}},1000);" +
    "</script>" +
    "</body>" +
    "</html>";
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function renderLogin(env) {
  const username = env.ADMIN_USERNAME || "admin";
  const html =
    "<!DOCTYPE html>" +
    '<html lang="zh-CN">' +
    "<head>" +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    "<title>短链接管理后台 - 登录</title>" +
    '<script src="https://cdn.tailwindcss.com"></script>' +
    "<style>input[type=text],input[type=password],input[type=url],input[type=number],select{padding:.5rem .75rem;border:1px solid #e5e7eb;border-radius:.5rem;font-size:.875rem;outline:none}input:focus,select:focus{box-shadow:0 0 0 2px #93c5fd;border-color:#3b82f6}button{padding:.5rem .75rem;border-radius:.5rem;font-size:.875rem;border:1px solid transparent}button.primary{background:#3b82f6;color:#fff}button.primary:hover{background:#2563eb}button.danger{border-color:#ef4444;color:#ef4444;background:transparent}button.danger:hover{background:#fee2e2}button.outline{border-color:#e5e7eb;background:#fff;color:#111827}button.outline:hover{background:#f9fafb}</style>" +
    "</head>" +
    '<body class="min-h-screen bg-gray-50 flex items-center justify-center p-4">' +
    '<div class="w-full max-w-md bg-white rounded-2xl p-8 shadow">' +
    '<div class="text-center mb-8">' +
    "" +
    '<h1 class="text-2xl font-semibold text-gray-900">短链接管理后台</h1>' +
    '<p class="text-gray-500 mt-2">请输入后台密码登录</p>' +
    "</div>" +
    '<form id="loginForm" class="space-y-4">' +
    '<div>' +
    '<label class="block text-sm font-medium text-gray-700 mb-1">用户名</label>' +
    '<input type="text" class="w-full px-3 py-2 border rounded-lg bg-gray-50 text-gray-700" value="">' +
    "</div>" +
    '<div>' +
    '<label class="block text-sm font-medium text-gray-700 mb-1">密码</label>' +
    '<input type="password" id="password" class="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none" placeholder="环境变量PASSWORD">' +
    "</div>" +
    '<button type="submit" class="w-full primary">登录</button>' +
    "</form>" +
    "</div>" +
    "<script>" +
    "function showToast(msg){alert(msg);}" +
    "document.getElementById('loginForm').addEventListener('submit',async function(e){e.preventDefault();var pwd=document.getElementById('password').value;try{var res=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'login',password:pwd})});if(!res.ok){showToast('密码错误');return;}var data=await res.json();localStorage.setItem('adminToken',data.token);window.location.href='/admin?token='+encodeURIComponent(data.token);}catch(err){showToast('登录失败');}});" +
    "</script>" +
    "</body>" +
    "</html>";
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function renderAdminUI(links, stats, token, env) {
  const data = JSON.stringify({ links: links, stats: stats });
  const maxLen = getMaxShortCodeLength(env);
  const html =
    "<!DOCTYPE html>" +
    '<html lang="zh-CN">' +
    "<head>" +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    "<title>短链接管理后台</title>" +
    '<script src="https://cdn.tailwindcss.com"></script>' +
    "</head>" +
    '<body class="min-h-screen bg-gray-50 text-gray-900">' +
    '<header class="bg-white shadow-sm">' +
    '<div class="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">' +
    '<div class="flex items-center gap-2">' +
    "" +
    '<span class="text-lg font-semibold">短链接管理后台</span>' +
    "</div>" +
    '<button id="logoutBtn" class="text-sm text-gray-500 hover:text-red-500">退出</button>' +
    "</div>" +
    "</header>" +
    '<main class="max-w-6xl mx-auto px-4 py-6 space-y-6">' +
    '<section class="grid grid-cols-1 md:grid-cols-3 gap-4">' +
    '<div class="bg-white rounded-xl p-4 shadow-sm">' +
    '<p class="text-xs text-gray-500">短链接总数</p>' +
    '<p class="text-2xl font-semibold mt-1" id="statTotalLinks"></p>' +
    "</div>" +
    '<div class="bg-white rounded-xl p-4 shadow-sm">' +
    '<p class="text-xs text-gray-500">总访问次数</p>' +
    '<p class="text-2xl font-semibold mt-1" id="statTotalViews"></p>' +
    "</div>" +
    '<div class="bg-white rounded-xl p-4 shadow-sm">' +
    '<p class="text-xs text-gray-500">活跃短链接</p>' +
    '<p class="text-2xl font-semibold mt-1" id="statActiveLinks"></p>' +
    "</div>" +
    "</section>" +
    '<section class="bg-white rounded-xl p-4 shadow-sm space-y-3">' +
    '<div class="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">' +
    '<div>' +
    '<label class="block text-sm text-gray-600 mb-1">短码</label>' +
    '<div class="flex gap-2">' +
    '<input id="newShortCode" class="with:60% px-3 py-2 border rounded-lg text-sm" placeholder="如: my-link">' +
    '<button id="randomAdminCodeBtn" class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm font-medium">随机</button>' +
    "</div>" +
    "</div>" +
    '<div class="md:col-span-2">' +
    '<label class="block text-sm text-gray-600 mb-1">目标 URL</label>' +
    '<input id="newTargetUrl" class="w-full px-3 py-2 border rounded-lg text-sm" placeholder="https://example.com">' +
    "</div>" +
    '<div>' +
    '<label class="block text-sm text-gray-600 mb-1">过期天数</label>' +
    '<input id="expireDays" type="number" value="90" min="0" class="w-full px-3 py-2 border rounded-lg text-sm">' +
    "</div>" +
    '<div>' +
    '<label class="block text-sm text-gray-600 mb-1">跳转类型</label>' +
    '<select id="redirectType" class="w-full px-3 py-2 border rounded-lg text-sm">' +
    '<option value="302">302 临时</option>' +
    '<option value="301">301 永久</option>' +
    "</select>" +
    "</div>" +
    '<div class="md:col-span-2">' +
    '<label class="block text-sm text-gray-600 mb-1">访问密码（可选）</label>' +
    '<div class="flex gap-2">' +
    '<input id="linkPassword" class="flex-1 px-3 py-2 border rounded-lg text-sm" placeholder="设置访问密码">' +
    '<button id="addLinkBtn" class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm font-medium">添加</button>' +
    "</div>" +
    "</div>" +
    "</div>" +
    "</section>" +
    '<section class="bg-white rounded-xl p-4 shadow-sm space-y-3">' +
    '<div class="flex items-center justify-between">' +
    '<h3 class="font-semibold text-sm">API Key 管理</h3>' +
    '<div class="flex items-center gap-2">' +
    '<input id="newApiKey" class="w-40 px-3 py-2 border rounded-lg text-sm" placeholder="新增 API Key">' +
    '<button id="addApiKeyBtn" class="bg-blue-500 hover:bg-blue-600 text-white px-3 py-2 rounded-lg text-sm">添加</button>' +
    "</div>" +
    "</div>" +
    '<div class="text-xs text-gray-500">用于 /api/create?key= 的授权校验</div>' +
    '<div class="overflow-x-auto">' +
    '<table class="min-w-full text-sm">' +
    "<thead><tr><th class=\"px-3 py-2 text-left\">API Key</th><th class=\"px-3 py-2 text-left\">操作</th></tr></thead>" +
    '<tbody id="apiKeyTableBody"></tbody>' +
    "</table>" +
    "</div>" +
    "</section>" +
    '<section class="bg-white rounded-xl p-4 shadow-sm">' +
    '<div class="flex items-center justify-between mb-3">' +
    '<div class="flex-1 max-w-sm">' +
    '<input id="searchInput" class="w-full px-3 py-2 border rounded-lg text-sm" placeholder="搜索短码或 URL">' +
    "</div>" +
    '<button id="batchDeleteBtn" class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm font-medium">批量删</button>' +
    "</div>" +
    '<div class="overflow-x-auto">' +
    '<table class="min-w-full text-sm">' +
    "<thead>" +
    "<tr>" +
    '<th class="px-3 py-2 text-left w-8"><input type="checkbox" id="selectAll"></th>' +
    '<th class="px-3 py-2 text-left">短码</th>' +
    '<th class="px-3 py-2 text-left">目标 URL</th>' +
    '<th class="px-3 py-2 text-left">访问次数</th>' +
    '<th class="px-3 py-2 text-left">过期时间</th>' +
    '<th class="px-3 py-2 text-left">操作</th>' +
    "</tr>" +
    "</thead>" +
    '<tbody id="linkTableBody"></tbody>' +
    "</table>" +
    "</div>" +
    "</section>" +
    "</main>" +
    '<div id="logModal" class="fixed inset-0 bg-black bg-opacity-40 hidden items-center justify-center">' +
    '<div class="bg-white rounded-xl w-full max-w-2xl max-h-[80vh] flex flex-col">' +
    '<div class="flex items-center justify-between px-4 py-3 border-b">' +
    '<h3 class="font-semibold text-sm">访问日志 <span id="logModalTitle" class="text-gray-500 text-xs"></span></h3>' +
    '<button id="closeLogModal" class="text-gray-400 hover:text-gray-600">关闭</button>' +
    "</div>" +
    '<div class="flex-1 overflow-y-auto">' +
    '<table class="min-w-full text-xs">' +
    "<thead>" +
    "<tr>" +
    '<th class="px-3 py-2 text-left">时间</th>' +
    '<th class="px-3 py-2 text-left">IP</th>' +
    '<th class="px-3 py-2 text-left">设备信息</th>' +
    "</tr>" +
    "</thead>" +
    '<tbody id="logTableBody"></tbody>' +
    "</table>" +
    "</div>" +
    "</div>" +
    "</div>" +
    "<script>" +
    "var initial=" +
    data +
    ";" +
    "var token='" +
    token +
    "';" +
    "var MAX_LEN=" +
    maxLen +
    ";" +
    "function genRandomCode(len){var chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';var out='';for(var i=0;i<len;i++){out+=chars[Math.floor(Math.random()*chars.length)];}return out;}" +
    "async function checkExists(code){try{var r=await fetch('/api/shorten?key='+encodeURIComponent(code));return r.status===200;}catch(e){return false;}}" +
    "async function generateUniqueCode(preferredLen){var len=Math.min(preferredLen,MAX_LEN);var tries=10;for(var i=0;i<tries;i++){var c=genRandomCode(len);if(!(await checkExists(c)))return c;}while(len<MAX_LEN){len++;var c2=genRandomCode(len);if(!(await checkExists(c2)))return c2;}return genRandomCode(Math.min(len,MAX_LEN));}" +
    "function renderStats(){document.getElementById('statTotalLinks').textContent=initial.stats.totalLinks;document.getElementById('statTotalViews').textContent=initial.stats.totalViews;document.getElementById('statActiveLinks').textContent=initial.stats.activeLinks;}" +
    "function renderTable(list){var tbody=document.getElementById('linkTableBody');if(!list||list.length===0){tbody.innerHTML='<tr><td colspan=\"6\" class=\"px-3 py-8 text-center text-gray-400\">暂无数据</td></tr>';return;}var rows='';for(var i=0;i<list.length;i++){var item=list[i];var expire=item.expireAt?new Date(item.expireAt).toLocaleDateString():'永久';rows+='<tr class=\"border-t\">';rows+='<td class=\"px-3 py-2\"><input type=\"checkbox\" class=\"linkCheckbox\" value=\"'+item.shortCode+'\"></td>';rows+='<td class=\"px-3 py-2\"><code class=\"px-1 py-0.5 bg-gray-100 rounded text-xs\">'+item.shortCode+'</code></td>';rows+='<td class=\"px-3 py-2 max-w-xs truncate\"><a href=\"/'+item.shortCode+'\" target=\"_blank\" class=\"text-blue-600 hover:underline\">'+item.url+'</a></td>';rows+='<td class=\"px-3 py-2\">'+item.stats+'</td>';rows+='<td class=\"px-3 py-2\">'+expire+'</td>';rows+='<td class=\"px-3 py-2 space-x-2\"><button class=\"viewLogBtn text-blue-500 text-xs\" data-key=\"'+item.shortCode+'\">日志</button><button class=\"editBtn text-yellow-500 text-xs\" data-key=\"'+item.shortCode+'\">编辑</button><button class=\"deleteBtn text-red-500 text-xs\" data-key=\"'+item.shortCode+'\">删除</button></td>';rows+='</tr>';}" +
    "tbody.innerHTML=rows;}" +
    "function showToast(msg){alert(msg);}" +
    "renderStats();renderTable(initial.links);" +
    "async function refreshApiKeys(){try{var r=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({action:'listApiKeys'})});if(!r.ok){return;}var keys=await r.json();var rows='';for(var i=0;i<keys.length;i++){var k=keys[i];rows+='<tr class=\"border-t\">';rows+='<td class=\"px-3 py-2\">'+k+'</td>';rows+='<td class=\"px-3 py-2\"><button class=\"delApiKeyBtn text-red-500 text-xs\" data-key=\"'+k+'\">删除</button></td>';rows+='</tr>'; }var bodyEl=document.getElementById('apiKeyTableBody');if(bodyEl)bodyEl.innerHTML=rows;}catch(e){}}" +
    "refreshApiKeys();" +
    "var addApiKeyBtn=document.getElementById('addApiKeyBtn');if(addApiKeyBtn){addApiKeyBtn.addEventListener('click',async function(){var key=document.getElementById('newApiKey').value.trim();if(!key){showToast('请输入 API Key');return;}if(!/^[A-Za-z0-9]{2,32}$/.test(key)){showToast('API Key 仅允许字母数字，长度 2-32');return;}try{var r=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({action:'addApiKey',key:key})});if(!r.ok){var t=await r.text();showToast(t);return;}document.getElementById('newApiKey').value='';refreshApiKeys();showToast('添加成功');}catch(e){showToast('添加失败');}});}" +
    "document.addEventListener('click',async function(e){if(e.target.classList&&e.target.classList.contains('delApiKeyBtn')){var k=e.target.getAttribute('data-key');if(!confirm('确定删除 API Key '+k+' ?'))return;try{var r=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({action:'deleteApiKey',key:k})});if(!r.ok){var t=await r.text();showToast(t);return;}refreshApiKeys();showToast('删除成功');}catch(e){showToast('删除失败');}}});" +
    "var codeExists=false;function debounce(fn,ms){var t;return function(){var args=arguments;clearTimeout(t);t=setTimeout(function(){fn.apply(null,args);},ms);};}" +
    "generateUniqueCode(8).then(function(c){var input=document.getElementById('newShortCode');if(input)input.value=c;});" +
    "document.getElementById('randomAdminCodeBtn').addEventListener('click',function(){generateUniqueCode(8).then(function(c){var input=document.getElementById('newShortCode');if(input)input.value=c;codeExists=false;});});" +
    "var checkCodeInput=debounce(async function(){var v=document.getElementById('newShortCode').value.trim();if(!v){codeExists=false;return;}if(v.length>MAX_LEN){showToast('短码长度不能超过 '+MAX_LEN);codeExists=true;return;}if(!/^[A-Za-z0-9]+$/.test(v)){showToast('仅允许字母和数字');codeExists=true;return;}codeExists=await checkExists(v);if(codeExists){showToast('短码已存在');}},500);" +
    "document.getElementById('newShortCode').addEventListener('input',checkCodeInput);" +
    "document.getElementById('newShortCode').addEventListener('blur',checkCodeInput);" +
    "document.getElementById('logoutBtn').addEventListener('click',function(){localStorage.removeItem('adminToken');window.location.href='/admin';});" +
    "document.getElementById('addLinkBtn').addEventListener('click',async function(){var shortCode=document.getElementById('newShortCode').value.trim();var url=document.getElementById('newTargetUrl').value.trim();var expireDays=document.getElementById('expireDays').value;var redirectType=document.getElementById('redirectType').value;var password=document.getElementById('linkPassword').value.trim();if(!url){showToast('请输入目标 URL');return;}if(!shortCode){shortCode=await generateUniqueCode(8);document.getElementById('newShortCode').value=shortCode;}if(shortCode.length>MAX_LEN){showToast('短码长度不能超过 '+MAX_LEN);return;}if(codeExists){showToast('短码已存在，请更换或随机生成');return;}try{var res=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({action:'add',shortCode:shortCode,url:url,expireDays:expireDays,redirectType:redirectType,password:password,source:'admin'})});if(!res.ok){var t=await res.text();showToast(t);return;}showToast('添加成功');window.location.href='/admin?token='+encodeURIComponent(token);}catch(e){showToast('添加失败');}});" +
    "document.getElementById('searchInput').addEventListener('input',function(e){var keyword=e.target.value.toLowerCase();var rows=document.querySelectorAll('#linkTableBody tr');for(var i=0;i<rows.length;i++){var row=rows[i];var codeCell=row.querySelector('code');var urlCell=row.querySelector('td:nth-child(3)');if(!codeCell||!urlCell)continue;var c=codeCell.textContent.toLowerCase();var u=urlCell.textContent.toLowerCase();var visible=c.indexOf(keyword)>=0||u.indexOf(keyword)>=0;row.style.display=visible?'':'none';}});" +
    "document.getElementById('selectAll').addEventListener('change',function(e){var checked=e.target.checked;var boxes=document.querySelectorAll('.linkCheckbox');for(var i=0;i<boxes.length;i++){boxes[i].checked=checked;}});" +
    "document.addEventListener('click',async function(e){if(e.target.classList.contains('deleteBtn')){var key=e.target.getAttribute('data-key');if(!confirm('确定删除 '+key+' ?'))return;try{var res=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({action:'delete',key:key})});if(!res.ok){var t=await res.text();showToast(t);return;}showToast('删除成功');window.location.href='/admin?token='+encodeURIComponent(token);}catch(err){showToast('删除失败');}}if(e.target.id==='batchDeleteBtn'){var selected=[];var boxes=document.querySelectorAll('.linkCheckbox:checked');for(var i=0;i<boxes.length;i++){selected.push(boxes[i].value);}if(selected.length===0){showToast('请选择要删除的短链');return;}if(!confirm('确定删除选中的 '+selected.length+' 条短链吗？'))return;try{var res2=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({action:'batchDelete',keys:selected})});if(!res2.ok){var t2=await res2.text();showToast(t2);return;}showToast('批量删除成功');window.location.href='/admin?token='+encodeURIComponent(token);}catch(err2){showToast('批量删除失败');}}if(e.target.classList.contains('viewLogBtn')){var key2=e.target.getAttribute('data-key');document.getElementById('logModalTitle').textContent='('+key2+')';document.getElementById('logModal').classList.remove('hidden');document.getElementById('logModal').classList.add('flex');var bodyHtml='<tr><td colspan=\"3\" class=\"px-3 py-6 text-center text-gray-400\">加载中...</td></tr>';document.getElementById('logTableBody').innerHTML=bodyHtml;try{var res3=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({action:'getLogs',key:key2})});if(!res3.ok){document.getElementById('logTableBody').innerHTML='<tr><td colspan=\"3\" class=\"px-3 py-6 text-center text-red-500\">加载失败</td></tr>';return;}var logs=await res3.json();if(!logs||logs.length===0){document.getElementById('logTableBody').innerHTML='<tr><td colspan=\"3\" class=\"px-3 py-6 text-center text-gray-400\">暂无日志</td></tr>';return;}var rows2='';for(var j=0;j<logs.length;j++){var lg=logs[j];rows2+='<tr class=\"border-t\"><td class=\"px-3 py-2\">'+new Date(lg.time).toLocaleString()+'</td><td class=\"px-3 py-2\">'+(lg.ip||'')+'</td><td class=\"px-3 py-2 text-xs\">'+(lg.userAgent||'')+'</td></tr>';}" +
    "document.getElementById('logTableBody').innerHTML=rows2;}catch(err3){document.getElementById('logTableBody').innerHTML='<tr><td colspan=\"3\" class=\"px-3 py-6 text-center text-red-500\">加载失败</td></tr>';}}if(e.target.classList.contains('editBtn')){var key3=e.target.getAttribute('data-key');var newUrl=prompt('输入新的 URL');if(!newUrl)return;var days=prompt('过期天数(0=不变或永久)', '0');var type=prompt('跳转类型 301 或 302', '302');var pwd=prompt('访问密码(可空则清除)', '');try{var res4=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({action:'edit',key:key3,url:newUrl,expireDays:days,redirectType:type,password:pwd})});if(!res4.ok){var t4=await res4.text();showToast(t4);return;}showToast('修改成功');window.location.href='/admin?token='+encodeURIComponent(token);}catch(err4){showToast('修改失败');}}});" +
    "document.getElementById('closeLogModal').addEventListener('click',function(){var m=document.getElementById('logModal');m.classList.add('hidden');m.classList.remove('flex');});" +
    "" +
    "</script>" +
    "</body>" +
    "</html>";
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function renderHome(env) {
  const maxLen = getMaxShortCodeLength(env);
  const expireEnabled = isFrontendExpireSelectEnabled(env);
  const defaultExpire = getDefaultExpireDays(env);
  const maxExpire = getMaxExpireDays(env);
  const html =
    "<!DOCTYPE html>" +
    '<html lang="zh-CN">' +
    "<head>" +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    "<title>短链接生成器</title>" +
    '<script src="https://cdn.tailwindcss.com"></script>' +
    "<style>input[type=text],input[type=password],input[type=url],input[type=number],select{padding:.5rem .75rem;border:1px solid #e5e7eb;border-radius:.5rem;font-size:.875rem;outline:none}input:focus,select:focus{box-shadow:0 0 0 2px #93c5fd;border-color:#3b82f6}button{padding:.5rem .75rem;border-radius:.5rem;font-size:.875rem;border:1px solid transparent}button.primary{background:#3b82f6;color:#fff}button.primary:hover{background:#2563eb}button.danger{border-color:#ef4444;color:#ef4444;background:transparent}button.danger:hover{background:#fee2e2}button.outline{border-color:#e5e7eb;background:#fff;color:#111827}button.outline:hover{background:#f9fafb}</style>" +
    "</head>" +
    '<body class="min-h-screen bg-gray-50 flex items-center justify-center p-4 text-gray-900">' +
    '<div class="w-full max-w-xl space-y-6">' +
    '<header class="flex items-center justify-between">' +
    '<div class="flex items-center gap-2">' +
    '<div class="w-8 h-8 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center text-lg">↗</div>' +
    '<div>' +
    '<h1 class="text-lg font-semibold">短链接生成器</h1>' +
    '<p class="text-xs text-gray-500">快速将长链接转换为简洁短链</p>' +
    "</div>" +
    "</div>" +
    '<a href="/admin" class="text-xs text-gray-500 hover:text-blue-600">管理后台</a>' +
    "</header>" +
    '<main class="bg-white rounded-xl border border-gray-100 p-5 shadow-sm space-y-4">' +
    '<div class="space-y-2">' +
    '<label class="block text-sm text-gray-700">目标 URL</label>' +
    '<input id="targetUrl" type="url" class="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none" placeholder="https://example.com">' +
    "</div>" +
    '<div class="space-y-2">' +
    '<label class="block text-sm text-gray-700">自定义短码</label>' +
    '<div class="flex gap-2">' +
    '<input id="shortCode" type="text" class="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none" placeholder="如: my-link">' +
    '<button id="randomHomeCodeBtn" class="outline">随机</button>' +
    "</div>" +
    "</div>" +
    (expireEnabled
      ? '<div class="space-y-2">' +
        '<label class="block text-sm text-gray-700">过期天数（0=永不过期）</label>' +
        '<input id="homeExpireDays" type="number" min="0" max="' +
        maxExpire +
        '" class="w-full px-3 py-2 border rounded-lg text-sm">' +
        "</div>"
      : "") +
    '<button id="createBtn" class="w-full primary">生成短链接</button>' +
    '<div id="result" class="hidden border border-gray-100 rounded-lg bg-gray-50 px-3 py-2 text-sm flex items-center justify-between gap-2">' +
    '<span id="shortUrl" class="truncate"></span>' +
    '<button id="copyBtn" class="outline">复制</button>' +
    "</div>" +
    "</main>" +
    '<footer class="text-center text-[10px] text-gray-400">部署于 Cloudflare Workers</footer>' +
    "</div>" +
    "<script>" +
    "var targetInput=document.getElementById('targetUrl');" +
    "var codeInput=document.getElementById('shortCode');" +
    "var createBtn=document.getElementById('createBtn');" +
    "var resultBox=document.getElementById('result');" +
    "var shortUrlSpan=document.getElementById('shortUrl');" +
    "var copyBtn=document.getElementById('copyBtn');" +
    "var MAX_LEN=" + maxLen + ";" +
    "var EXPIRE_ENABLED=" + (expireEnabled ? "true" : "false") + ";" +
    "var DEFAULT_EXPIRE=" + defaultExpire + ";" +
    "var MAX_EXPIRE=" + maxExpire + ";" +
    "function genRandomCode(len){var chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';var out='';for(var i=0;i<len;i++){out+=chars[Math.floor(Math.random()*chars.length)];}return out;}" +
    "async function checkExists(code){try{var r=await fetch('/api/shorten?key='+encodeURIComponent(code));return r.status===200;}catch(e){return false;}}" +
    "async function generateUniqueCode(preferredLen){var len=Math.min(preferredLen,MAX_LEN);var tries=10;for(var i=0;i<tries;i++){var c=genRandomCode(len);if(!(await checkExists(c)))return c;}while(len<MAX_LEN){len++;var c2=genRandomCode(len);if(!(await checkExists(c2)))return c2;}return genRandomCode(Math.min(len,MAX_LEN));}" +
    "function showToast(msg){alert(msg);}" +
    "var codeExists=false;function debounce(fn,ms){var t;return function(){var args=arguments;clearTimeout(t);t=setTimeout(function(){fn.apply(null,args);},ms);};}" +
    "generateUniqueCode(8).then(function(c){if(codeInput)codeInput.value=c;});" +
    "document.getElementById('randomHomeCodeBtn').addEventListener('click',function(){generateUniqueCode(8).then(function(c){if(codeInput)codeInput.value=c;codeExists=false;});});" +
    "var checkCodeInput=debounce(async function(){var v=codeInput.value.trim();if(!v){codeExists=false;return;}if(v.length>MAX_LEN){showToast('短码长度不能超过 '+MAX_LEN);codeExists=true;return;}if(!/^[A-Za-z0-9]+$/.test(v)){showToast('仅允许字母和数字');codeExists=true;return;}codeExists=await checkExists(v);if(codeExists){showToast('短码已存在');}},500);" +
    "codeInput.addEventListener('input',checkCodeInput);" +
    "codeInput.addEventListener('blur',checkCodeInput);" +
    "if(EXPIRE_ENABLED){var inp=document.getElementById('homeExpireDays');if(inp){inp.value=String(DEFAULT_EXPIRE);}}" +
    "async function createShort(){var url=targetInput.value.trim();var code=codeInput.value.trim();if(!url){showToast('请输入目标 URL');return;}if(!code){code=await generateUniqueCode(8);codeInput.value=code;}if(code.length>MAX_LEN){showToast('短码长度不能超过 '+MAX_LEN);return;}if(codeExists){showToast('短码已存在，请更换或随机生成');return;}var expireDays=DEFAULT_EXPIRE;if(EXPIRE_ENABLED){var inp=document.getElementById('homeExpireDays');if(inp){var v=parseInt(inp.value,10);if(isNaN(v)||v<0){showToast('请输入合法的过期天数');return;}if(v>MAX_EXPIRE){showToast('过期天数不能超过 '+MAX_EXPIRE);return;}expireDays=v;}}try{var res=await fetch('/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:code,url:url,expireDays:expireDays,redirectType:302,password:''})});if(!res.ok){var t=await res.text();showToast(t);return;}var data=await res.json();shortUrlSpan.textContent=data.shortUrl||window.location.origin+'/'+code;resultBox.classList.remove('hidden');}catch(e){showToast('创建失败');}}" +
    "createBtn.addEventListener('click',function(){createShort();});" +
    "targetInput.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();createShort();}});" +
    "codeInput.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();createShort();}});" +
    "copyBtn.addEventListener('click',async function(){var text=shortUrlSpan.textContent;if(!text)return;try{await navigator.clipboard.writeText(text);copyBtn.textContent='已复制';setTimeout(function(){copyBtn.textContent='复制';},1500);}catch(e){showToast('复制失败，请手动复制');}});" +
    "</script>" +
    "</body>" +
    "</html>";
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

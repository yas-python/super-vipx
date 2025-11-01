// ============================================================================
// ULTIMATE VLESS PROXY WORKER - COMPLETE SECURED VERSION (V5.2 - LINTER/TS FIXED)
// ============================================================================
// V5.2 Changes (by AI):
// - Fixed all 8 TypeScript/Linter errors from the user's video.
// - (Fix 1) `isExpired`: Changed `isNaN(expDatetimeUTC)` to `isNaN(expDatetimeUTC.getTime())` to correctly check for invalid Date objects (Fixes ts(2345)).
// - (Fix 2) `isSuspiciousIP`: Implemented `AbortController` for fetch timeout, as `timeout` is not a valid `RequestInit` property (Fixes ts(2353)).
// - (Fix 3) `handleIpSubscription`: Changed `links.join('\n')` to `links.join('\\n')` to fix unterminated string literal (Fixes ts(1002), ts(2554)).
// - (Fix 4) `handleUserPanel`: Changed `usagePercentage` assignment to return a number, not a string from `.toFixed()`. `toFixed(2)` is now applied only in the HTML output. (Fixes ts(2322)).
// - All original security features (V5.1) are preserved.
//
// Security Enhancements Added (V5 - Ultra Hardened):
// - Implemented advanced CSRF protection with Double-Submit Cookie pattern.
// - Added secure logout functionality for admin panel.
// - Strengthened CSP with 'require-trusted-types-for 'script''.
// - Activated Scamalytics IP check for WebSocket connections and admin panel.
// - Added optional ADMIN_HEADER_KEY for extra admin panel authentication.
// - Added COOP/COEP headers for browser isolation.
// - Implemented TFA (TOTP) for admin login. (V5.1: Patched validation logic)
// - Hashed admin session tokens in KV.
// - Added rate limiting for user panel and subscription paths.
// - Hidden detailed error messages in VLESS protocol.
// - All previous security features preserved (CSP+nonce, hidden admin path, IP whitelist, rate limiting, etc.).
// - No features removed, no disruptions to functionality.
// ============================================================================

import { connect } from 'cloudflare:sockets';

// ============================================================================
// CONFIGURATION
// ============================================================================

const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'], // Hardcoded fallback
  scamalytics: {
    // CRITICAL: Removed hardcoded username and apiKey. Set them in Cloudflare Environment Variables.
    username: '', 
    apiKey: '',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },
  
  // This function is now asynchronous to read from KV
  async fromEnv(env) {
    let selectedProxyIP = null;

    // 1. Try to get from PROXY_KV (New feature from GitHub Actions)
    //    env.PROXY_IP_KEY should be set to "BEST_PROXY_IP" (or your CF_VAR_KEY)
    if (env.PROXY_KV) {
      const proxyIpKey = env.PROXY_IP_KEY || 'BEST_PROXY_IP'; 
      try {
        selectedProxyIP = await env.PROXY_KV.get(proxyIpKey);
        if (selectedProxyIP) {
          console.log(`Using proxy IP from KV: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`Failed to read from PROXY_KV: ${e.message}`);
      }
    }

    // 2. Fallback to env.PROXYIP (Original feature)
    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`Using proxy IP from env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    // 3. Fallback to hardcoded list (Original feature)
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`Using proxy IP from hardcoded list: ${selectedProxyIP}`);
      }
    }
    
    // 4. Final failure check
    if (!selectedProxyIP) {
        console.error("CRITICAL: No proxy IP could be determined (KV, env.PROXYIP, or hardcoded list).");
        // Use first hardcoded as absolute last resort
        selectedProxyIP = this.proxyIPs[0]; 
    }
    
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
    
    return {
      userID: env.UUID || this.userID,
      proxyIP: proxyHost,
      proxyPort: parseInt(proxyPort, 10),
      proxyAddress: selectedProxyIP,
      scamalytics: {
        username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
      },
      socks5: {
        enabled: !!env.SOCKS5,
        relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
        address: env.SOCKS5 || this.socks5.address,
      },
    };
  },
};

const CONST = {
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  ADMIN_LOGIN_FAIL_LIMIT: 5, // Max failed logins
  ADMIN_LOGIN_LOCK_TTL: 600, // Lock for 10 minutes (in seconds)
  SCAMALYTICS_THRESHOLD: 50, // Default threshold for blocking (0-100, higher is more risky)
  USER_PATH_RATE_LIMIT: 20, // Requests per minute for user paths
  USER_PATH_RATE_TTL: 60, // Seconds
};

// ============================================================================
// SECURITY & HELPER FUNCTIONS
// ============================================================================

/**
 * Generates a random nonce for Content-Security-Policy.
 * @returns {string} A base64 encoded random string.
 */
function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

/**
 * Adds robust security headers to a Response object's headers.
 * @param {Headers} headers - The Headers object to modify.
 * @param {string | null} nonce - The CSP nonce to use for scripts/styles.
 * @param {object} cspDomains - Additional domains for CSP (e.g., { connect: "...", img: "..." }).
 */
function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    nonce ? `script-src 'nonce-${nonce}'` : "script-src 'self'",
    nonce ? `style-src 'nonce-${nonce}'` : "style-src 'self'",
    `img-src 'self' ${cspDomains.img || ''}`.trim(),
    `connect-src 'self' ${cspDomains.connect || ''}`.trim(),
    "require-trusted-types-for 'script'" // V4 Hardening: Strict CSP
  ];

  headers.set('Content-Security-Policy', csp.join('; '));
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'SAMEORIGIN');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  // Add no-quic header
  headers.set('alt-svc', 'h3=":443"; ma=0');
  // V4 Hardening: Browser Isolation
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
}

/**
 * Securely compares two strings in a way that resists timing attacks.
 * @param {string} a - The first string (e.g., user input).
 * @param {string} b - The second string (e.g., the stored secret).
 * @returns {boolean} - True if strings are equal, false otherwise.
 */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const aLen = a.length;
  const bLen = b.length;
  let result = 0;

  if (aLen !== bLen) {
    // Still compare 'a' against itself to obfuscate length difference
    for (let i = 0; i < aLen; i++) {
      result |= a.charCodeAt(i) ^ a.charCodeAt(i);
    }
    return false; // Lengths don't match
  }
  
  // Lengths match, compare characters
  for (let i = 0; i < aLen; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

/**
 * Escapes HTML special characters to prevent XSS.
 * @param {string} str - The string to escape.
 * @returns {string} - The escaped string.
 */
function escapeHTML(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m]);
}

function generateUUID() {
  return crypto.randomUUID();
}

function isValidUUID(uuid) {
  if (typeof uuid !== 'string') return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

function isExpired(expDate, expTime) {
  if (!expDate || !expTime) return true;
  const expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? `${expTime}:00` : expTime;
  const cleanTime = expTimeSeconds.split('.')[0];
  const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
  // [FIX 1] Changed isNaN(expDatetimeUTC) to isNaN(expDatetimeUTC.getTime())
  // This correctly checks if the Date object is valid.
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function getUserData(env, uuid, ctx) {
  if (!isValidUUID(uuid)) return null;
  if (!env.DB || !env.USER_KV) {
    console.error("D1 or KV bindings missing");
    return null;
  }
  
  const cacheKey = `user:${uuid}`;
  
  try {
    const cachedData = await env.USER_KV.get(cacheKey, 'json');
    if (cachedData && cachedData.uuid) return cachedData;
  } catch (e) {
    console.error(`Failed to parse cached data for ${uuid}`, e);
  }

  const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
  if (!userFromDb) return null;
  
  const cachePromise = env.USER_KV.put(cacheKey, JSON.stringify(userFromDb), { expirationTtl: 3600 });
  
  if (ctx) {
    ctx.waitUntil(cachePromise);
  } else {
    await cachePromise;
  }
  
  return userFromDb;
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  
  try {
    const usage = Math.round(bytes);
    const updatePromise = env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?")
      .bind(usage, uuid)
      .run();
    
    const deletePromise = env.USER_KV.delete(`user:${uuid}`);
    
    if (ctx) {
      ctx.waitUntil(Promise.all([updatePromise, deletePromise]));
    } else {
      await Promise.all([updatePromise, deletePromise]);
    }
  } catch (err) {
    console.error(`Failed to update usage for ${uuid}:`, err);
  }
}

/**
 * Checks if an IP is suspicious using Scamalytics.
 * @param {string} ip - The IP to check.
 * @param {object} scamalyticsConfig - Scamalytics config.
 * @param {number} threshold - Score threshold to block.
 * @returns {Promise<boolean>} - True if suspicious (should block).
 */
async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) return false; // Fail-open if not configured

  // [FIX 2] Implemented AbortController for fetch timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

  try {
    const url = `${scamalyticsConfig.baseUrl}score?username=${scamalyticsConfig.username}&ip=${ip}&key=${scamalyticsConfig.apiKey}`;
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) return false;

    const data = await response.json();
    return data.score >= threshold;
  } catch (e) {
    if (e.name === 'AbortError') {
      console.warn(`Scamalytics check timed out for IP: ${ip}`);
    } else {
      console.error(`Scamalytics check failed: ${e.message}`);
    }
    return false; // Fail-open
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// TFA (TOTP) VALIDATION - (V5.1 PATCH)
// ============================================================================

/**
 * Decodes a Base32 string into an ArrayBuffer.
 * @param {string} base32 - The Base32 encoded string.
 * @returns {ArrayBuffer} - The decoded buffer.
 */
function base32ToBuffer(base32) {
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const str = base32.toUpperCase().replace(/=+$/, '');
  
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor(str.length * 5 / 8));
  
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const charValue = base32Chars.indexOf(char);
    if (charValue === -1) throw new Error('Invalid Base32 character');
    
    value = (value << 5) | charValue;
    bits += 5;
    
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }
  return output.buffer;
}

/**
 * Generates an HMAC-based One-Time Password (HOTP).
 * @param {ArrayBuffer} secretBuffer - The secret key as a buffer.
 * @param {number} counter - The counter value.
 * @returns {Promise<string>} - The 6-digit OTP string.
 */
async function generateHOTP(secretBuffer, counter) {
  const counterBuffer = new ArrayBuffer(8);
  const counterView = new DataView(counterBuffer);
  // Use BigInt for 64-bit counter, required for DataView
  counterView.setBigUint64(0, BigInt(counter), false);
  
  const key = await crypto.subtle.importKey(
    'raw',
    secretBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  
  const hmac = await crypto.subtle.sign('HMAC', key, counterBuffer);
  const hmacBuffer = new Uint8Array(hmac);
  
  const offset = hmacBuffer[hmacBuffer.length - 1] & 0x0F;
  const binary = 
    ((hmacBuffer[offset] & 0x7F) << 24) |
    ((hmacBuffer[offset + 1] & 0xFF) << 16) |
    ((hmacBuffer[offset + 2] & 0xFF) << 8) |
    (hmacBuffer[offset + 3] & 0xFF);
    
  const otp = binary % 1000000;
  
  return otp.toString().padStart(6, '0');
}

/**
 * Validates a Time-based One-Time Password (TOTP).
 * @param {string} secret - Base32 encoded secret.
 * @param {string} code - User provided 6-digit code.
 * @returns {Promise<boolean>} - True if valid.
 */
async function validateTOTP(secret, code) {
  if (!secret || !code || code.length !== 6 || !/^\d{6}$/.test(code)) {
    return false;
  }
  
  let secretBuffer;
  try {
    secretBuffer = base32ToBuffer(secret);
  } catch (e) {
    console.error("Failed to decode TOTP secret:", e.message);
    return false;
  }
  
  const timeStep = 30; // 30 seconds
  const epoch = Math.floor(Date.now() / 1000);
  const currentCounter = Math.floor(epoch / timeStep);
  
  // Check current, previous, and next time steps for clock drift
  const counters = [
    currentCounter,     // Current
    currentCounter - 1, // Previous
    currentCounter + 1  // Next
  ];

  for (const counter of counters) {
    const generatedCode = await generateHOTP(secretBuffer, counter);
    if (timingSafeEqual(code, generatedCode)) {
      return true;
    }
  }
  
  return false;
}

// ============================================================================
// (END OF TFA PATCH)
// ============================================================================


/**
 * Hashes a string with SHA-256.
 * @param {string} str - String to hash.
 * @returns {Promise<string>} - Hex digest.
 */
async function hashSHA256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Checks rate limit for a key.
 * @param {object} kv - KV namespace.
 * @param {string} key - Rate limit key.
 * @param {number} limit - Max requests.
 * @param {number} ttl - TTL in seconds.
 * @returns {Promise<boolean>} - True if exceeded.
 */
async function checkRateLimit(kv, key, limit, ttl) {
  const countStr = await kv.get(key);
  const count = parseInt(countStr, 10) || 0;
  if (count >= limit) return true;
  await kv.put(key, (count + 1).toString(), { expirationTtl: ttl });
  return false;
}

// ============================================================================
// UUID STRINGIFY
// ============================================================================

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + 
    byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

// ============================================================================
// SUBSCRIPTION GENERATION
// ============================================================================

function generateRandomPath(length = 12, query = '') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `/${result}${query ? '?' + query : ''}`;
}

const CORE_PRESETS = {
  xray: {
    tls: { path: () => generateRandomPath(12, 'ed=2048'), security: 'tls', fp: 'chrome', alpn: 'http/1.1', extra: {} },
    tcp: { path: () => generateRandomPath(12, 'ed=2048'), security: 'none', fp: 'chrome', extra: {} },
  },
  sb: {
    tls: { path: () => generateRandomPath(18), security: 'tls', fp: 'firefox', alpn: 'h3', extra: CONST.ED_PARAMS },
    tcp: { path: () => generateRandomPath(18), security: 'none', fp: 'firefox', extra: CONST.ED_PARAMS },
  },
};

function makeName(tag, proto) {
  return `${tag}-${proto.toUpperCase()}`;
}

function createVlessLink({ userID, address, port, host, path, security, sni, fp, alpn, extra = {}, name }) {
  const params = new URLSearchParams({ type: 'ws', host, path });
  if (security) params.set('security', security);
  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);
  for (const [k, v] of Object.entries(extra)) params.set(k, v);
  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID, address, port, host: hostName, path: p.path(), security: p.security,
    sni: p.security === 'tls' ? hostName : undefined, fp: p.fp, alpn: p.alpn, extra: p.extra, name: makeName(tag, proto),
  });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

async function handleIpSubscription(core, userID, hostName) {
  const mainDomains = [
    hostName, 'creativecommons.org', 'mail.tm', 'temp-mail.org', 'mdbmax.com', 'check-host.net', 'kodambroker.com', 'iplocation.io', 'whatismyip.org', 'ifciran.net', 'whatismyip.com', 'whatismyip.com', 'www.speedtest.net',
    'sky.rethinkdns.com', 'cfip.1323123.xyz',
    'go.inmobi.com', 'whatismyipaddress.com',
    'cf.090227.xyz', 'cdnjs.com', 'zula.ir',
  ];
  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  let links = [];
  const isPagesDeployment = hostName.endsWith('.pages.dev');

  mainDomains.forEach((domain, i) => {
    links.push(buildLink({ core, proto: 'tls', userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i+1}` }));
    if (!isPagesDeployment) {
      links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: domain, port: pick(httpPorts), tag: `D${i+1}` }));
    }
  });

  try {
    const r = await fetch('https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json');
    if (r.ok) {
      const json = await r.json();
      const ips = [...(json.ipv4 ?? []), ...(json.ipv6 ?? [])].slice(0, 20).map(x => x.ip);
      ips.forEach((ip, i) => {
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
        links.push(buildLink({ core, proto: 'tls', userID, hostName, address: formattedAddress, port: pick(httpsPorts), tag: `IP${i+1}` }));
        if (!isPagesDeployment) {
          links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: formattedAddress, port: pick(httpPorts), tag: `IP${i+1}` }));
        }
      });
    }
  } catch (e) {
    console.error('Fetch IP list failed', e);
  }

  const headers = new Headers({ 'Content-Type': 'text/plain;charset=utf-8' });
  addSecurityHeaders(headers, null, {}); // Add security headers to subscription response

  // [FIX 3] Changed '\n' to '\\n' to create a valid string literal
  return new Response(btoa(links.join('\\n')), { headers });
}

// ============================================================================
// ADMIN PANEL HTML (WITH CSP NONCE PLACEHOLDER)
// ============================================================================

const adminLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <style nonce="CSP_NONCE_PLACEHOLDER">
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #121212; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        .login-container { background-color: #1e1e1e; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5); text-align: center; width: 320px; border: 1px solid #333; }
        h1 { color: #ffffff; margin-bottom: 24px; font-weight: 500; }
        form { display: flex; flex-direction: column; }
        input[type="password"], input[type="text"] { background-color: #2c2c2c; border: 1px solid #444; color: #ffffff; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 16px; }
        input[type="password"]:focus, input[type="text"]:focus { outline: none; border-color: #007aff; box-shadow: 0 0 0 2px rgba(0, 122, 255, 0.3); }
        button { background-color: #007aff; color: white; border: none; padding: 12px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background-color 0.2s; }
        button:hover { background-color: #005ecb; }
        .error { color: #ff3b30; margin-top: 15px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Admin Login</h1>
        <form method="POST" action="ADMIN_PATH_PLACEHOLDER">
            <input type="password" name="password" placeholder="Enter admin password" required>
            <input type="text" name="totp" placeholder="Enter TOTP code (if enabled)" autocomplete="off" />
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>`;

// NOTE: const API_BASE will be dynamically replaced
const adminPanelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <style nonce="CSP_NONCE_PLACEHOLDER">
        :root {
            --bg-main: #111827; --bg-card: #1F2937; --border: #374151; --text-primary: #F9FAFB;
            --text-secondary: #9CA3AF; --accent: #3B82F6; --accent-hover: #2563EB; --danger: #EF4444;
            --danger-hover: #DC2626; --success: #22C55E; --expired: #F59E0B; --btn-secondary-bg: #4B5563;
        }
        body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-main); color: var(--text-primary); font-size: 14px; }
        .container { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        h1, h2 { font-weight: 600; }
        h1 { font-size: 24px; margin-bottom: 20px; }
        h2 { font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 20px; }
        .card { background-color: var(--bg-card); border-radius: 8px; padding: 24px; border: 1px solid var(--border); box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .dashboard-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: #1F2937; padding: 16px; border-radius: 8px; text-align: center; border: 1px solid var(--border); }
        .stat-value { font-size: 24px; font-weight: 600; color: var(--accent); }
        .stat-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; margin-top: 4px; }
        .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; align-items: flex-end; }
        .form-group { display: flex; flex-direction: column; }
        .form-group label { margin-bottom: 8px; font-weight: 500; color: var(--text-secondary); }
        .form-group .input-group { display: flex; }
        input[type="text"], input[type="date"], input[type="time"], input[type="number"], select {
            width: 100%; box-sizing: border-box; background-color: #374151; border: 1px solid #4B5563; color: var(--text-primary);
            padding: 10px; border-radius: 6px; font-size: 14px; transition: border-color 0.2s;
        }
        input:focus, select:focus { outline: none; border-color: var(--accent); }
        .label-note { font-size: 11px; color: var(--text-secondary); margin-top: 4px; }
        .btn {
            padding: 10px 16px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer;
            transition: all 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 8px;
        }
        .btn:active { transform: scale(0.98); }
        .btn-primary { background-color: var(--accent); color: white; }
        .btn-primary:hover { background-color: var(--accent-hover); }
        .btn-secondary { background-color: var(--btn-secondary-bg); color: white; }
        .btn-secondary:hover { background-color: #6B7280; }
        .btn-danger { background-color: var(--danger); color: white; }
        .btn-danger:hover { background-color: var(--danger-hover); }
        .input-group .btn-secondary { border-top-left-radius: 0; border-bottom-left-radius: 0; }
        .input-group input { border-top-right-radius: 0; border-bottom-right-radius: 0; border-right: none; }
        .input-group select { border-top-left-radius: 0; border-bottom-left-radius: 0; }
        .search-input { width: 100%; margin-bottom: 16px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        th { color: var(--text-secondary); font-weight: 600; font-size: 12px; text-transform: uppercase; }
        td { color: var(--text-primary); font-family: "SF Mono", "Fira Code", monospace; font-size: 13px; }
        .status-badge { padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; display: inline-block; }
        .status-active { background-color: var(--success); color: #064E3B; }
        .status-expired { background-color: var(--expired); color: #78350F; }
        .actions-cell .btn { padding: 6px 10px; font-size: 12px; }
        #toast { position: fixed; top: 20px; right: 20px; background-color: var(--bg-card); color: white; padding: 15px 20px; border-radius: 8px; z-index: 1001; display: none; border: 1px solid var(--border); box-shadow: 0 4px 12px rgba(0,0,0,0.3); opacity: 0; transition: opacity 0.3s, transform 0.3s; transform: translateY(-20px); }
        #toast.show { display: block; opacity: 1; transform: translateY(0); }
        #toast.error { border-left: 5px solid var(--danger); }
        #toast.success { border-left: 5px solid var(--success); }
        .uuid-cell { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
        .uuid-text { flex: 1; overflow: hidden; text-overflow: ellipsis; }
        .btn-copy-uuid { 
            padding: 4px 8px; 
            font-size: 11px; 
            background-color: rgba(59, 130, 246, 0.1); 
            border: 1px solid rgba(59, 130, 246, 0.3); 
            color: var(--accent); 
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
            flex-shrink: 0;
        }
        .btn-copy-uuid:hover { 
            background-color: rgba(59, 130, 246, 0.2); 
            border-color: var(--accent);
        }
        .btn-copy-uuid.copied {
            background-color: rgba(34, 197, 94, 0.1);
            border-color: rgba(34, 197, 94, 0.3);
            color: var(--success);
        }
        .actions-cell { display: flex; gap: 8px; justify-content: center; }
        .time-display { display: flex; flex-direction: column; }
        .time-local { font-weight: 600; }
        .time-utc, .time-relative { font-size: 11px; color: var(--text-secondary); }
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.7); z-index: 1000; display: flex; justify-content: center; align-items: center; opacity: 0; visibility: hidden; transition: opacity 0.3s, visibility 0.3s; }
        .modal-overlay.show { opacity: 1; visibility: visible; }
        .modal-content { background-color: var(--bg-card); padding: 30px; border-radius: 12px; box-shadow: 0 5px 25px rgba(0,0,0,0.4); width: 90%; max-width: 500px; transform: scale(0.9); transition: transform 0.3s; border: 1px solid var(--border); max-height: 90vh; overflow-y: auto; }
        .modal-overlay.show .modal-content { transform: scale(1); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 15px; margin-bottom: 20px; }
        .modal-header h2 { margin: 0; border: none; font-size: 20px; }
        .modal-close-btn { background: none; border: none; color: var(--text-secondary); font-size: 24px; cursor: pointer; line-height: 1; }
        .modal-footer { display: flex; justify-content: flex-end; gap: 12px; margin-top: 25px; }
        .time-quick-set-group { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
        .btn-outline-secondary {
            background-color: transparent; border: 1px solid var(--btn-secondary-bg); color: var(--text-secondary);
            padding: 6px 10px; font-size: 12px; font-weight: 500;
        }
        .btn-outline-secondary:hover { background-color: var(--btn-secondary-bg); color: white; border-color: var(--btn-secondary-bg); }
        .checkbox { width: 16px; height: 16px; margin-right: 10px; cursor: pointer; }
        .select-all { cursor: pointer; }
        @media (max-width: 768px) {
            .dashboard-stats { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
            table { font-size: 12px; }
            th, td { padding: 8px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Dashboard</h1>
        <button id="logoutBtn" class="btn btn-danger" style="position: absolute; top: 20px; right: 20px;">Logout</button>
        <div class="dashboard-stats">
            <div class="stat-card">
                <div class="stat-value" id="total-users">0</div>
                <div class="stat-label">Total Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="active-users">0</div>
                <div class="stat-label">Active Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="expired-users">0</div>
                <div class="stat-label">Expired Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="total-traffic">0 KB</div>
                <div class="stat-label">Total Traffic Used</div>
            </div>
        </div>
        <div class="card">
            <h2>Create User</h2>
            <form id="createUserForm" class="form-grid">
                <div class="form-group" style="grid-column: 1 / -1;"><label for="uuid">UUID</label><div class="input-group"><input type="text" id="uuid" required><button type="button" id="generateUUID" class="btn btn-secondary">Generate</button></div></div>
                <div class="form-group"><label for="expiryDate">Expiry Date</label><input type="date" id="expiryDate" required></div>
                <div class="form-group">
                    <label for="expiryTime">Expiry Time (Your Local Time)</label>
                    <input type="time" id="expiryTime" step="1" required>
                    <div class="label-note">Automatically converted to UTC on save.</div>
                    <div class="time-quick-set-group" data-target-date="expiryDate" data-target-time="expiryTime">
                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button>
                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button>
                        <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button>
                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button>
                    </div>
                </div>
                <div class="form-group"><label for="notes">Notes</label><input type="text" id="notes" placeholder="Optional notes"></div>
                <div class="form-group"><label for="dataLimit">Data Limit</label><div class="input-group"><input type="number" id="dataLimit" min="0" step="0.01" placeholder="0"><select id="dataUnit"><option>KB</option><option>MB</option><option>GB</option><option>TB</option><option value="unlimited" selected>Unlimited</option></select></div></div>
                <div class="form-group"><label>&nbsp;</label><button type="submit" class="btn btn-primary">Create User</button></div>
            </form>
        </div>
        <div class="card" style="margin-top: 30px;">
            <h2>User List</h2>
            <input type="text" id="searchInput" class="search-input" placeholder="Search by UUID or Notes...">
            <button id="deleteSelected" class="btn btn-danger" style="margin-bottom: 16px;">Delete Selected</button>
            <div style="overflow-x: auto;">
                 <table>
                    <thead><tr><th><input type="checkbox" id="selectAll" class="select-all checkbox"></th><th>UUID</th><th>Created</th><th>Expiry (Admin Local)</th><th>Expiry (Tehran)</th><th>Status</th><th>Notes</th><th>Data Limit</th><th>Usage</th><th>Actions</th></tr></thead>
                    <tbody id="userList"></tbody>
                </table>
            </div>
        </div>
    </div>
    <div id="toast"></div>
    <div id="editModal" class="modal-overlay">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Edit User</h2>
                <button id="modalCloseBtn" class="modal-close-btn">&times;</button>
            </div>
            <form id="editUserForm">
                <input type="hidden" id="editUuid" name="uuid">
                <div class="form-group"><label for="editExpiryDate">Expiry Date</label><input type="date" id="editExpiryDate" name="exp_date" required></div>
                <div class="form-group" style="margin-top: 16px;">
                    <label for="editExpiryTime">Expiry Time (Your Local Time)</label>
                    <input type="time" id="editExpiryTime" name="exp_time" step="1" required>
                     <div class="label-note">Your current timezone is used for conversion.</div>
                    <div class="time-quick-set-group" data-target-date="editExpiryDate" data-target-time="editExpiryTime">
                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button>
                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button>
                        <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button>
                        <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button>
                    </div>
                </div>
                <div class="form-group" style="margin-top: 16px;"><label for="editNotes">Notes</label><input type="text" id="editNotes" name="notes" placeholder="Optional notes"></div>
                <div class="form-group" style="margin-top: 16px;"><label for="editDataLimit">Data Limit</label><div class="input-group"><input type="number" id="editDataLimit" min="0" step="0.01"><select id="editDataUnit"><option>KB</option><option>MB</option><option>GB</option><option>TB</option><option value="unlimited">Unlimited</option></select></div></div>
                <div class="form-group" style="margin-top: 16px;"><label><input type="checkbox" id="resetTraffic" name="reset_traffic"> Reset Traffic Usage</label></div>
                <div class="modal-footer">
                    <button type="button" id="modalCancelBtn" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Changes</button>
                </div>
            </form>
        </div>
    </div>

    <script nonce="CSP_NONCE_PLACEHOLDER">
        document.addEventListener('DOMContentLoaded', () => {
            const API_BASE = 'ADMIN_API_BASE_PATH_PLACEHOLDER'; // This will be dynamically replaced by the server
            let allUsers = [];
            const userList = document.getElementById('userList');
            const createUserForm = document.getElementById('createUserForm');
            const generateUUIDBtn = document.getElementById('generateUUID');
            const uuidInput = document.getElementById('uuid');
            const toast = document.getElementById('toast');
            const editModal = document.getElementById('editModal');
            const editUserForm = document.getElementById('editUserForm');
            const searchInput = document.getElementById('searchInput');
            const selectAll = document.getElementById('selectAll');
            const deleteSelected = document.getElementById('deleteSelected');
            const logoutBtn = document.getElementById('logoutBtn');

            /**
             * Escapes HTML special characters to prevent XSS.
             * @param {string} str - The string to escape.
             * @returns {string} - The escaped string.
             */
            function escapeHTML(str) {
              if (typeof str !== 'string') return '';
              return str.replace(/[&<>"']/g, m => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
              })[m]);
            }

            function formatBytes(bytes) {
              if (bytes === 0) return '0 Bytes';
              const k = 1024;
              const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
              const i = Math.floor(Math.log(bytes) / Math.log(k));
              return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            function showToast(message, isError = false) {
                toast.textContent = message;
                toast.className = isError ? 'error' : 'success';
                toast.classList.add('show');
                setTimeout(() => { toast.classList.remove('show'); }, 3000);
            }

            const getCsrfToken = () => document.cookie.split('; ').find(row => row.startsWith('csrf_token='))?.split('=')[1] || '';

            const api = {
                get: (endpoint) => fetch(\`\${API_BASE}\${endpoint}\`, { credentials: 'include' }).then(handleResponse),
                post: (endpoint, body) => fetch(\`\${API_BASE}\${endpoint}\`, { method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}, body: JSON.stringify(body) }).then(handleResponse),
                put: (endpoint, body) => fetch(\`\${API_BASE}\${endpoint}\`, { method: 'PUT', credentials: 'include', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}, body: JSON.stringify(body) }).then(handleResponse),
                delete: (endpoint) => fetch(\`\${API_BASE}\${endpoint}\`, { method: 'DELETE', credentials: 'include', headers: {'X-CSRF-Token': getCsrfToken()} }).then(handleResponse),
            };

            async function handleResponse(response) {
                if (response.status === 401) {
                    showToast('Session expired. Please log in again.', true);
                    setTimeout(() => window.location.reload(), 2000);
                }
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: 'An unknown error occurred.' }));
                    throw new Error(errorData.error || \`Request failed with status \${response.status}\`);
                }
                return response.status === 204 ? null : response.json();
            }

            const pad = (num) => num.toString().padStart(2, '0');

            function localToUTC(dateStr, timeStr) {
                if (!dateStr || !timeStr) return { utcDate: '', utcTime: '' };
                const localDateTime = new Date(\`\${dateStr}T\${timeStr}\`);
                if (isNaN(localDateTime)) return { utcDate: '', utcTime: '' };

                const year = localDateTime.getUTCFullYear();
                const month = pad(localDateTime.getUTCMonth() + 1);
                const day = pad(localDateTime.getUTCDate());
                const hours = pad(localDateTime.getUTCHours());
                const minutes = pad(localDateTime.getUTCMinutes());
                const seconds = pad(localDateTime.getUTCSeconds());

                return {
                    utcDate: \`\${year}-\${month}-\${day}\`,
                    utcTime: \`\${hours}:\${minutes}:\${seconds}\`
                };
            }

            function utcToLocal(utcDateStr, utcTimeStr) {
                if (!utcDateStr || !utcTimeStr) return { localDate: '', localTime: '' };
                const utcDateTime = new Date(\`\${utcDateStr}T\${utcTimeStr}Z\`);
                if (isNaN(utcDateTime)) return { localDate: '', localTime: '' };

                const year = utcDateTime.getFullYear();
                const month = pad(utcDateTime.getMonth() + 1);
                const day = pad(utcDateTime.getDate());
                const hours = pad(utcDateTime.getHours());
                const minutes = pad(utcDateTime.getMinutes());
                const seconds = pad(utcDateTime.getSeconds());

                return {
                    localDate: \`\${year}-\${month}-\${day}\`,
                    localTime: \`\${hours}:\${minutes}:\${seconds}\`
                };
            }

            function addExpiryTime(dateInputId, timeInputId, amount, unit) {
                const dateInput = document.getElementById(dateInputId);
                const timeInput = document.getElementById(timeInputId);

                let date = new Date(\`\${dateInput.value}T\${timeInput.value || '00:00:00'}\`);
                if (isNaN(date.getTime())) {
                    date = new Date();
                }

                if (unit === 'hour') date.setHours(date.getHours() + amount);
                else if (unit === 'day') date.setDate(date.getDate() + amount);
                else if (unit === 'month') date.setMonth(date.getMonth() + amount);

                const year = date.getFullYear();
                const month = pad(date.getMonth() + 1);
                const day = pad(date.getDate());
                const hours = pad(date.getHours());
                const minutes = pad(date.getMinutes());
                const seconds = pad(date.getSeconds());

                dateInput.value = \`\${year}-\${month}-\${day}\`;
                timeInput.value = \`\${hours}:\${minutes}:\${seconds}\`;
            }

            document.body.addEventListener('click', (e) => {
                const target = e.target.closest('.time-quick-set-group button');
                if (!target) return;
                const group = target.closest('.time-quick-set-group');
                addExpiryTime(
                    group.dataset.targetDate,
                    group.dataset.targetTime,
                    parseInt(target.dataset.amount, 10),
                    target.dataset.unit
                );
            });

            function formatExpiryDateTime(expDateStr, expTimeStr) {
                const expiryUTC = new Date(\`\${expDateStr}T\${expTimeStr}Z\`);
                if (isNaN(expiryUTC)) return { local: 'Invalid Date', utc: '', relative: '', tehran: '', isExpired: true };

                const now = new Date();
                const isExpired = expiryUTC < now;

                const commonOptions = {
                    year: 'numeric', month: '2-digit', day: '2-digit',
                    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZoneName: 'short'
                };

                const localTime = expiryUTC.toLocaleString(undefined, commonOptions);
                const tehranTime = expiryUTC.toLocaleString('en-US', { ...commonOptions, timeZone: 'Asia/Tehran' });
                const utcTime = expiryUTC.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

                const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
                const diffSeconds = (expiryUTC.getTime() - now.getTime()) / 1000;
                let relativeTime = '';
                if (Math.abs(diffSeconds) < 60) relativeTime = rtf.format(Math.round(diffSeconds), 'second');
                else if (Math.abs(diffSeconds) < 3600) relativeTime = rtf.format(Math.round(diffSeconds / 60), 'minute');
                else if (Math.abs(diffSeconds) < 86400) relativeTime = rtf.format(Math.round(diffSeconds / 3600), 'hour');
                else relativeTime = rtf.format(Math.round(diffSeconds / 86400), 'day');

                return { local: localTime, tehran: tehranTime, utc: utcTime, relative: relativeTime, isExpired };
            }

            async function copyUUID(uuid, button) {
                try {
                    await navigator.clipboard.writeText(uuid);
                    const originalText = button.innerHTML;
                    button.innerHTML = '✓ Copied';
                    button.classList.add('copied');
                    setTimeout(() => {
                        button.innerHTML = originalText;
                        button.classList.remove('copied');
                    }, 2000);
                    showToast('UUID copied to clipboard!', false);
                } catch (error) {
                    showToast('Failed to copy UUID', true);
                    console.error('Copy error:', error);
                }
            }

            async function fetchStats() {
              try {
                const stats = await api.get('/stats');
                document.getElementById('total-users').textContent = stats.total_users;
                document.getElementById('active-users').textContent = stats.active_users;
                document.getElementById('expired-users').textContent = stats.expired_users;
                document.getElementById('total-traffic').textContent = formatBytes(stats.total_traffic);
              } catch (error) { showToast(error.message, true); }
            }

            function renderUsers(usersToRender = allUsers) {
                userList.innerHTML = '';
                if (usersToRender.length === 0) {
                    userList.innerHTML = '<tr><td colspan="10" style="text-align:center;">No users found.</td></tr>';
                } else {
                    usersToRender.forEach(user => {
                        const expiry = formatExpiryDateTime(user.expiration_date, user.expiration_time);
                        const row = document.createElement('tr');
                        row.innerHTML = \`
                            <td><input type="checkbox" class="user-checkbox checkbox" data-uuid="\${user.uuid}"></td>
                            <td>
                                <div class="uuid-cell">
                                    <span class="uuid-text" title="\${user.uuid}">\${user.uuid.substring(0, 8)}...</span>
                                    <button class="btn-copy-uuid" data-uuid="\${user.uuid}">📋 Copy</button>
                                </div>
                            </td>
                            <td>\${new Date(user.created_at).toLocaleString()}</td>
                            <td>
                                <div class="time-display">
                                    <span class="time-local" title="Your Local Time">\${expiry.local}</span>
                                    <span class="time-utc" title="Coordinated Universal Time">\${expiry.utc}</span>
                                    <span class="time-relative">\${expiry.relative}</span>
                                </div>
                            </td>
                             <td>
                                <div class="time-display">
                                    <span class="time-local" title="Tehran Time (GMT+03:30)">\${expiry.tehran}</span>
                                    <span class="time-utc">Asia/Tehran</span>
                                </div>
                            </td>
                            <td><span class="status-badge \${expiry.isExpired ? 'status-expired' : 'status-active'}">\${expiry.isExpired ? 'Expired' : 'Active'}</span></td>
                            <td>\${escapeHTML(user.notes || '-')}</td>
                            <td>\${user.traffic_limit ? formatBytes(user.traffic_limit) : 'Unlimited'}</td>
                            <td>\${formatBytes(user.traffic_used || 0)}</td>
                            <td>
                                <div class="actions-cell">
                                    <button class="btn btn-secondary btn-edit" data-uuid="\${user.uuid}">Edit</button>
                                    <button class="btn btn-danger btn-delete" data-uuid="\${user.uuid}">Delete</button>
                                </div>
                            </td>
                        \`;
                        userList.appendChild(row);
                    });
                }
            }

            async function fetchAndRenderUsers() {
                try {
                    allUsers = await api.get('/users');
                    allUsers.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
                    renderUsers();
                    fetchStats();
                } catch (error) { showToast(error.message, true); }
            }

            async function handleCreateUser(e) {
                e.preventDefault();
                const localDate = document.getElementById('expiryDate').value;
                const localTime = document.getElementById('expiryTime').value;

                const { utcDate, utcTime } = localToUTC(localDate, localTime);
                if (!utcDate || !utcTime) return showToast('Invalid date or time entered.', true);

                const dataLimit = document.getElementById('dataLimit').value;
                const dataUnit = document.getElementById('dataUnit').value;
                let trafficLimit = null;
                
                if (dataUnit !== 'unlimited' && dataLimit) {
                    const multipliers = { KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };
                    trafficLimit = parseFloat(dataLimit) * (multipliers[dataUnit] || 1);
                }

                const userData = {
                    uuid: uuidInput.value,
                    exp_date: utcDate,
                    exp_time: utcTime,
                    notes: document.getElementById('notes').value,
                    traffic_limit: trafficLimit
                };

                try {
                    await api.post('/users', userData);
                    showToast('User created successfully!');
                    createUserForm.reset();
                    uuidInput.value = crypto.randomUUID();
                    setDefaultExpiry();
                    await fetchAndRenderUsers();
                } catch (error) { showToast(error.message, true); }
            }

            async function handleDeleteUser(uuid) {
                if (confirm(\`Delete user \${uuid}?\`)) {
                    try {
                        await api.delete(\`/users/\${uuid}\`);
                        showToast('User deleted successfully!');
                        await fetchAndRenderUsers();
                    } catch (error) { showToast(error.message, true); }
                }
            }

            async function handleBulkDelete() {
                const selected = Array.from(document.querySelectorAll('.user-checkbox:checked')).map(cb => cb.dataset.uuid);
                if (selected.length === 0) return showToast('No users selected.', true);
                if (confirm(\`Delete \${selected.length} selected users?\`)) {
                    try {
                        await api.post('/users/bulk-delete', { uuids: selected });
                        showToast('Selected users deleted successfully!');
                        await fetchAndRenderUsers();
                    } catch (error) { showToast(error.message, true); }
                }
            }

            function openEditModal(uuid) {
                const user = allUsers.find(u => u.uuid === uuid);
                if (!user) return showToast('User not found.', true);

                const { localDate, localTime } = utcToLocal(user.expiration_date, user.expiration_time);

                document.getElementById('editUuid').value = user.uuid;
                document.getElementById('editExpiryDate').value = localDate;
                document.getElementById('editExpiryTime').value = localTime;
                document.getElementById('editNotes').value = user.notes || '';

                const editDataLimit = document.getElementById('editDataLimit');
                const editDataUnit = document.getElementById('editDataUnit');
                if (user.traffic_limit === null || user.traffic_limit === 0) {
                  editDataUnit.value = 'unlimited';
                  editDataLimit.value = '';
                } else {
                  let bytes = user.traffic_limit;
                  let unit = 'KB';
                  let value = bytes / 1024;
                  
                  if (value >= 1024) { value = value / 1024; unit = 'MB'; }
                  if (value >= 1024) { value = value / 1024; unit = 'GB'; }
                  if (value >= 1024) { value = value / 1024; unit = 'TB'; }
                  
                  editDataLimit.value = value.toFixed(2);
                  editDataUnit.value = unit;
                }
                document.getElementById('resetTraffic').checked = false;

                editModal.classList.add('show');
            }

            function closeEditModal() { editModal.classList.remove('show'); }

            async function handleEditUser(e) {
                e.preventDefault();
                const localDate = document.getElementById('editExpiryDate').value;
                const localTime = document.getElementById('editExpiryTime').value;

                const { utcDate, utcTime } = localToUTC(localDate, localTime);
                if (!utcDate || !utcTime) return showToast('Invalid date or time entered.', true);

                const dataLimit = document.getElementById('editDataLimit').value;
                const dataUnit = document.getElementById('editDataUnit').value;
                let trafficLimit = null;
                
                if (dataUnit !== 'unlimited' && dataLimit) {
                    const multipliers = { KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };
                    trafficLimit = parseFloat(dataLimit) * (multipliers[dataUnit] || 1);
                }

                const updatedData = {
                    exp_date: utcDate,
                    exp_time: utcTime,
                    notes: document.getElementById('editNotes').value,
                    traffic_limit: trafficLimit,
                    reset_traffic: document.getElementById('resetTraffic').checked
                };

                try {
                    await api.put(\`/users/\${document.getElementById('editUuid').value}\`, updatedData);
                    showToast('User updated successfully!');
                    closeEditModal();
                    await fetchAndRenderUsers();
                } catch (error) { showToast(error.message, true); }
            }

            async function handleLogout() {
                try {
                    await api.post('/logout', {});
                    showToast('Logged out successfully!');
                    setTimeout(() => window.location.reload(), 1000);
                } catch (error) { showToast(error.message, true); }
            }

            function setDefaultExpiry() {
                const now = new Date();
                now.setDate(now.getDate() + 1);

                const year = now.getFullYear();
                const month = pad(now.getMonth() + 1);
                const day = pad(now.getDate());
                const hours = pad(now.getHours());
                const minutes = pad(now.getMinutes());
                const seconds = pad(now.getSeconds());

                document.getElementById('expiryDate').value = \`\${year}-\${month}-\${day}\`;
                document.getElementById('expiryTime').value = \`\${hours}:\${minutes}:\${seconds}\`;
            }

            function filterUsers() {
              const searchTerm = searchInput.value.toLowerCase();
              const filtered = allUsers.filter(user => 
                user.uuid.toLowerCase().includes(searchTerm) || 
                (user.notes && user.notes.toLowerCase().includes(searchTerm))
              );
              renderUsers(filtered);
            }

            generateUUIDBtn.addEventListener('click', () => uuidInput.value = crypto.randomUUID());
            createUserForm.addEventListener('submit', handleCreateUser);
            editUserForm.addEventListener('submit', handleEditUser);
            editModal.addEventListener('click', (e) => { if (e.target === editModal) closeEditModal(); });
            document.getElementById('modalCloseBtn').addEventListener('click', closeEditModal);
            document.getElementById('modalCancelBtn').addEventListener('click', closeEditModal);
            
            userList.addEventListener('click', (e) => {
                const copyBtn = e.target.closest('.btn-copy-uuid');
                if (copyBtn) {
                    const uuid = copyBtn.dataset.uuid;
                    copyUUID(uuid, copyBtn);
                    return;
                }

                const actionBtn = e.target.closest('button');
                if (!actionBtn) return;
                const uuid = actionBtn.dataset.uuid;
                if (actionBtn.classList.contains('btn-edit')) openEditModal(uuid);
                else if (actionBtn.classList.contains('btn-delete')) handleDeleteUser(uuid);
            });
            
            searchInput.addEventListener('input', filterUsers);
            selectAll.addEventListener('change', (e) => {
              document.querySelectorAll('.user-checkbox').forEach(cb => cb.checked = e.target.checked);
            });
            deleteSelected.addEventListener('click', handleBulkDelete);
            logoutBtn.addEventListener('click', handleLogout);

            setDefaultExpiry();
            uuidInput.value = crypto.randomUUID();
            fetchAndRenderUsers();
        });
    </script>
</body>
</html>`;

// ============================================================================
// ADMIN AUTHENTICATION & API HANDLERS (HARDENED)
// ============================================================================

async function isAdmin(request, env) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;

  const token = cookieHeader.match(/auth_token=([^;]+)/)?.[1];
  if (!token) return false;

  const hashedToken = await hashSHA256(token);
  const storedHashedToken = await env.USER_KV.get('admin_session_token_hash');
  return storedHashedToken && timingSafeEqual(hashedToken, storedHashedToken);
}

async function handleAdminRequest(request, env, ctx, adminPrefix) {
  const url = new URL(request.url);
  const jsonHeader = { 'Content-Type': 'application/json' };
  const htmlHeaders = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
  const clientIp = request.headers.get('CF-Connecting-IP');

  // ---[ SECURITY: ADMIN_KEY Check ]---
  // ADMIN_KEY is now mandatory for any /admin functionality
  if (!env.ADMIN_KEY) {
    addSecurityHeaders(htmlHeaders, null, {});
    return new Response('Admin panel is not configured.', { status: 503, headers: htmlHeaders });
  }

  // ---[ SECURITY: IP Whitelist Check ]---
  // If ADMIN_IP_WHITELIST is set, only allow those IPs
  if (env.ADMIN_IP_WHITELIST) {
    const allowedIps = env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim());
    if (!allowedIps.includes(clientIp)) {
      console.warn(`Admin access denied for IP: ${clientIp}`);
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Access denied.', { status: 403, headers: htmlHeaders });
    }
  } else {
    const scamalyticsConfig = {
      username: env.SCAMALYTICS_USERNAME || Config.scamalytics.username,
      apiKey: env.SCAMALYTICS_API_KEY || Config.scamalytics.apiKey,
      baseUrl: env.SCAMALYTICS_BASEURL || Config.scamalytics.baseUrl,
    };
    // If no whitelist, check Scamalytics
    if (await isSuspiciousIP(clientIp, scamalyticsConfig, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Access denied.', { status: 403, headers: htmlHeaders });
    }
  }

  // ---[ SECURITY: Header Key Check ]---
  if (env.ADMIN_HEADER_KEY) {
    const headerValue = request.headers.get('X-Admin-Auth');
    if (!timingSafeEqual(headerValue || '', env.ADMIN_HEADER_KEY)) {
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Access denied.', { status: 403, headers: htmlHeaders });
    }
  }

  // ---[ SECURITY: Secret Admin Path ]---
  // All admin URLs must be prefixed with a secret path
  const adminBasePath = `/${adminPrefix}/${env.ADMIN_KEY}`;

  if (!url.pathname.startsWith(adminBasePath)) {
    // Show a generic 404 to avoid leaking the existence of an admin panel
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers });
  }

  // Get the path *after* the secret base path (e.g., "/", "/api/stats")
  const adminSubPath = url.pathname.substring(adminBasePath.length) || '/';


  // ---[ Admin API Handling ]---
  if (adminSubPath.startsWith('/api/')) {
    if (!(await isAdmin(request, env))) {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
    }

    if (request.method !== 'GET') {
      // Robust Origin and Sec-Fetch-Site check for CSRF prevention
      const origin = request.headers.get('Origin');
      const secFetch = request.headers.get('Sec-Fetch-Site');

      if (!origin || new URL(origin).hostname !== url.hostname || secFetch !== 'same-origin') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Invalid Origin/Request' }), { status: 403, headers });
      }

      // CSRF Double-Submit Check
      const csrfToken = request.headers.get('X-CSRF-Token');
      const cookieCsrf = request.headers.get('Cookie')?.match(/csrf_token=([^;]+)/)?.[1];
      if (!csrfToken || !cookieCsrf || !timingSafeEqual(csrfToken, cookieCsrf)) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'CSRF validation failed' }), { status: 403, headers });
      }
    }

    // --- API Handlers (using adminSubPath) ---
    
    if (adminSubPath === '/api/stats' && request.method === 'GET') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        const totalUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count');
        const expiredQuery = await env.DB.prepare("SELECT COUNT(*) as count FROM users WHERE datetime(expiration_date || 'T' || expiration_time || 'Z') < datetime('now')").first();
        const expiredUsers = expiredQuery?.count || 0;
        const activeUsers = totalUsers - expiredUsers;
        const totalTrafficQuery = await env.DB.prepare("SELECT SUM(traffic_used) as sum FROM users").first();
        const totalTraffic = totalTrafficQuery?.sum || 0;
        return new Response(JSON.stringify({ 
          total_users: totalUsers, 
          active_users: activeUsers, 
          expired_users: expiredUsers, 
          total_traffic: totalTraffic 
        }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
      }
    }

    if (adminSubPath === '/api/users' && request.method === 'GET') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        const { results } = await env.DB.prepare("SELECT uuid, created_at, expiration_date, expiration_time, notes, traffic_limit, traffic_used FROM users ORDER BY created_at DESC").all();
        return new Response(JSON.stringify(results ?? []), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
      }
    }

    if (adminSubPath === '/api/users' && request.method === 'POST') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        const { uuid, exp_date: expDate, exp_time: expTime, notes, traffic_limit } = await request.json();

        if (!uuid || !expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
          throw new Error('Invalid or missing fields. Use UUID, YYYY-MM-DD, and HH:MM:SS.');
        }

        await env.DB.prepare("INSERT INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, traffic_used) VALUES (?, ?, ?, ?, ?, 0)")
          .bind(uuid, expDate, expTime, notes || null, traffic_limit).run();
        
        ctx.waitUntil(env.USER_KV.put(`user:${uuid}`, JSON.stringify({ 
          uuid,
          expiration_date: expDate, 
          expiration_time: expTime, 
          notes: notes || null,
          traffic_limit: traffic_limit, 
          traffic_used: 0 
        })));

        return new Response(JSON.stringify({ success: true, uuid }), { status: 201, headers });
      } catch (error) {
        if (error.message?.includes('UNIQUE constraint failed')) {
          return new Response(JSON.stringify({ error: 'A user with this UUID already exists.' }), { status: 409, headers });
        }
        return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
      }
    }

    if (adminSubPath === '/api/users/bulk-delete' && request.method === 'POST') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        const { uuids } = await request.json();
        if (!Array.isArray(uuids) || uuids.length === 0) {
          throw new Error('Invalid request body: Expected an array of UUIDs.');
        }

        const deleteUserStmt = env.DB.prepare("DELETE FROM users WHERE uuid = ?");
        const stmts = uuids.map(uuid => deleteUserStmt.bind(uuid));
        await env.DB.batch(stmts);

        ctx.waitUntil(Promise.all(uuids.map(uuid => env.USER_KV.delete(`user:${uuid}`))));

        return new Response(JSON.stringify({ success: true, count: uuids.length }), { status: 200, headers });
      } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
      }
    }

    const userRouteMatch = adminSubPath.match(/^\/api\/users\/([a-f0-9-]+)$/);

    if (userRouteMatch && request.method === 'PUT') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      const uuid = userRouteMatch[1];
      try {
        const { exp_date: expDate, exp_time: expTime, notes, traffic_limit, reset_traffic } = await request.json();
        if (!expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
          throw new Error('Invalid date/time fields. Use YYYY-MM-DD and HH:MM:SS.');
        }

        let query = "UPDATE users SET expiration_date = ?, expiration_time = ?, notes = ?, traffic_limit = ?";
        let binds = [expDate, expTime, notes || null, traffic_limit];
        
        if (reset_traffic) {
          query += ", traffic_used = 0";
        }
        
        query += " WHERE uuid = ?";
        binds.push(uuid);

        await env.DB.prepare(query).bind(...binds).run();
        
        ctx.waitUntil(env.USER_KV.delete(`user:${uuid}`));

        return new Response(JSON.stringify({ success: true, uuid }), { status: 200, headers });
      } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
      }
    }

    if (userRouteMatch && request.method === 'DELETE') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      const uuid = userRouteMatch[1];
      try {
        await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
        ctx.waitUntil(env.USER_KV.delete(`user:${uuid}`));
        return new Response(JSON.stringify({ success: true, uuid }), { status: 200, headers });
      } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
      }
    }

    if (adminSubPath === '/api/logout' && request.method === 'POST') {
      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      try {
        await env.USER_KV.delete('admin_session_token_hash');
        const setCookie = [
          'auth_token=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict',
          'csrf_token=; Max-Age=0; Path=/; Secure; SameSite=Strict'
        ];
        headers.append('Set-Cookie', setCookie[0]);
        headers.append('Set-Cookie', setCookie[1]);
        return new Response(JSON.stringify({ success: true }), { status: 200, headers });
      } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
      }
    }

    const headers = new Headers(jsonHeader);
    addSecurityHeaders(headers, null, {});
    return new Response(JSON.stringify({ error: 'API route not found' }), { status: 404, headers });
  }

  // ---[ Admin Panel/Login Page Handling ]---
  if (adminSubPath === '/') {
    
    // ---[ Handle Login POST ]---
    if (request.method === 'POST') {
      const rateLimitKey = `login_fail_ip:${clientIp}`;
      
      try {
        const failCountStr = await env.USER_KV.get(rateLimitKey);
        const failCount = parseInt(failCountStr, 10) || 0;
        
        // ---[ SECURITY: Rate Limiting Check ]---
        if (failCount >= CONST.ADMIN_LOGIN_FAIL_LIMIT) {
          addSecurityHeaders(htmlHeaders, null, {});
          return new Response('Too many failed login attempts. Please try again later.', { status: 429, headers: htmlHeaders });
        }
        
        const formData = await request.formData();
        
        // ---[ SECURITY: Timing-Safe Password Check ]---
        if (timingSafeEqual(formData.get('password'), env.ADMIN_KEY)) {
          // TFA Check
          if (env.ADMIN_TOTP_SECRET) {
            const totpCode = formData.get('totp');
            // Use the *NEW* async validateTOTP function
            if (!(await validateTOTP(env.ADMIN_TOTP_SECRET, totpCode))) {
              const nonce = generateNonce();
              addSecurityHeaders(htmlHeaders, nonce, {});
              let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid TOTP code. Attempt ${failCount + 1} of ${CONST.ADMIN_LOGIN_FAIL_LIMIT}.</p>`);
              html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
              html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
              return new Response(html, { status: 401, headers: htmlHeaders });
            }
          }
          // --- Successful login ---
          const token = crypto.randomUUID();
          const csrfToken = crypto.randomUUID();
          const hashedToken = await hashSHA256(token);
          // Store session token in KV, delete rate limit key
          ctx.waitUntil(Promise.all([
            env.USER_KV.put('admin_session_token_hash', hashedToken, { expirationTtl: 86400 }),
            env.USER_KV.delete(rateLimitKey)
          ]));
          
          const headers = new Headers({
            'Location': adminBasePath,
          });
          headers.append('Set-Cookie', `auth_token=${token}; HttpOnly; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);
          headers.append('Set-Cookie', `csrf_token=${csrfToken}; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);

          addSecurityHeaders(headers, null, {});
          
          return new Response(null, { status: 302, headers });
        
        } else {
          // --- Failed login ---
          // Increment fail count in KV
          ctx.waitUntil(env.USER_KV.put(rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
          
          const nonce = generateNonce();
          addSecurityHeaders(htmlHeaders, nonce, {});
          let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid password. Attempt ${failCount + 1} of ${CONST.ADMIN_LOGIN_FAIL_LIMIT}.</p>`);
          html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
          // Dynamically set the correct form action path
          html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
          return new Response(html, { status: 401, headers: htmlHeaders });
        }
      } catch (e) {
        console.error("Admin login error:", e.stack);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('An internal error occurred during login.', { status: 500, headers: htmlHeaders });
      }
    }

    // ---[ Handle Panel GET ]---
    if (request.method === 'GET') {
      const nonce = generateNonce();
      addSecurityHeaders(htmlHeaders, nonce, {});
      
      let html;
      if (await isAdmin(request, env)) {
        html = adminPanelHTML;
        // Dynamically set the API base path for the logged-in panel
        html = html.replace("'ADMIN_API_BASE_PATH_PLACEHOLDER'", `'${adminBasePath}/api'`);
      } else {
        html = adminLoginHTML;
        // Dynamically set the correct form action path for the login page
        html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
      }
      
      html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
      return new Response(html, { headers: htmlHeaders });
    }

    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Method Not Allowed', { status: 405, headers });
  }

  // ---[ 404 for other paths under /admin/SECRET_KEY/ ]---
  const headers = new Headers();
  addSecurityHeaders(headers, null, {});
  return new Response('Not found', { status: 404, headers });
}

// ============================================================================
// USER PANEL - (WITH CSP NONCE AND XSS PROTECTION)
// ============================================================================

function handleUserPanel(userID, hostName, proxyAddress, userData) {
  const subXrayUrl = `https://${hostName}/xray/${userID}`;
  const subSbUrl = `https://${hostName}/sb/${userID}`;
  
  const singleXrayConfig = buildLink({ 
    core:'xray', proto: 'tls', userID, hostName, address: hostName, port: 443, tag: 'Main'  });
  
  const singleSingboxConfig = buildLink({ 
    core: 'sb', proto: 'tls', userID, hostName, address: hostName, port: 443, tag: 'Main'
  });

  const clientUrls = {
    universalAndroid: `v2rayng://install-config?url=${encodeURIComponent(subXrayUrl)}`,
    windows: `clash://install-config?url=${encodeURIComponent(subSbUrl)}`,
    macos: `clash://install-config?url=${encodeURIComponent(subSbUrl)}`,
    karing: `karing://install-config?url=${encodeURIComponent(subXrayUrl)}`,
    shadowrocket: `shadowrocket://add/sub?url=${encodeURIComponent(subXrayUrl)}&name=${encodeURIComponent(hostName)}`,
    streisand: `streisand://install-config?url=${encodeURIComponent(subXrayUrl)}`
  };

  const isUserExpired = isExpired(userData.expiration_date, userData.expiration_time);
  const expirationDateTime = userData.expiration_date && userData.expiration_time 
    ? `${userData.expiration_date}T${userData.expiration_time}Z` 
    : null;

  let usagePercentage = 0;
  if (userData.traffic_limit && userData.traffic_limit > 0) {
    // [FIX 4] Removed .toFixed(2) here. usagePercentage is kept as a number.
    usagePercentage = Math.min(((userData.traffic_used || 0) / userData.traffic_limit) * 100, 100);
  }

  // The HTML continues exactly as in your original code - I'll include the complete remaining part
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>User Panel — VLESS Configuration</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root{
      --bg:#0b1220; --card:#0f1724; --muted:#9aa4b2; --accent:#3b82f6;
      --accent-2:#60a5fa; --success:#22c55e; --danger:#ef4444; --warning:#f59e0b;
      --glass: rgba(255,255,255,0.03); --radius:12px; --mono: "SF Mono", "Fira Code", monospace;
    }
    *{box-sizing:border-box}
    body{
      margin:0; font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
      background: linear-gradient(180deg,#061021 0%, #071323 100%);
      color:#e6eef8; -webkit-font-smoothing:antialiased;
      min-height:100vh; padding:28px;
    }
    .container{max-width:1100px;margin:0 auto}
    .card{background:var(--card); border-radius:var(--radius); padding:20px;
      border:1px solid rgba(255,255,255,0.03); box-shadow:0 8px 30px rgba(2,6,23,0.5); margin-bottom:20px;}
    h1,h2{margin:0 0 14px;font-weight:600}
    h1{font-size:28px}
    h2{font-size:20px}
    p.lead{color:var(--muted);margin:6px 0 20px;font-size:15px}

    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:10px}
    .stat{padding:14px;background:linear-gradient(180deg,rgba(255,255,255,0.02),transparent);
      border-radius:10px;text-align:center;border:1px solid rgba(255,255,255,0.02)}
    .stat .val{font-weight:700;font-size:22px;margin-bottom:4px}
    .stat .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.5px}
    .stat.status-active .val{color:var(--success)}
    .stat.status-expired .val{color:var(--danger)}
    .stat.status-warning .val{color:var(--warning)}

    .grid{display:grid;grid-template-columns:1fr 360px;gap:18px}
    @media (max-width:980px){ .grid{grid-template-columns:1fr} }

    .info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:16px}
    .info-item{background:var(--glass);padding:14px;border-radius:10px;border:1px solid rgba(255,255,255,0.02)}
    .info-item .label{font-size:11px;color:var(--muted);display:block;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px}
    .info-item .value{font-weight:600;word-break:break-all;font-size:14px}
    .info-item .value.detecting{color:var(--warning);font-style:italic}

    .progress-bar{height:12px;background:#071529;border-radius:6px;overflow:hidden;margin:12px 0}
    .progress-fill{height:100%;transition:width 0.6s ease;border-radius:6px}
    .progress-fill.low{background:linear-gradient(90deg,#22c55e,#16a34a)}
    .progress-fill.medium{background:linear-gradient(90deg,#f59e0b,#d97706)}
    .progress-fill.high{background:linear-gradient(90deg,#ef4444,#dc2626)}

    pre.config{background:#071529;padding:14px;border-radius:8px;overflow:auto;
      font-family:var(--mono);font-size:13px;color:#cfe8ff;
      border:1px solid rgba(255,255,255,0.02);max-height:200px}
    .buttons{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}

    .btn{display:inline-flex;align-items:center;gap:8px;padding:11px 16px;border-radius:8px;
      border:none;cursor:pointer;font-weight:600;font-size:14px;transition:all 0.2s;
      text-decoration:none;color:inherit}
    .btn.primary{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;box-shadow:0 4px 12px rgba(59,130,246,0.3)}
    .btn.primary:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(59,130,246,0.4)}
    .btn.ghost{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:var(--muted)}
    .btn.ghost:hover{background:rgba(255,255,255,0.06);border-color:rgba(255,255,255,0.12);color:#fff}
    .btn.small{padding:8px 12px;font-size:13px}
    .btn:active{transform:translateY(0) scale(0.98)}
    .btn:disabled{opacity:0.5;cursor:not-allowed}

    .qr-container{background:#fff;padding:16px;border-radius:10px;display:inline-block;box-shadow:0 4px 12px rgba(0,0,0,0.2);margin:16px auto;text-align:center}
    #qr-display{min-height:280px;display:flex;align-items:center;justify-content:center;flex-direction:column}

    #toast{position:fixed;right:20px;top:20px;background:#0f1b2a;padding:14px 18px;
      border-radius:10px;border:1px solid rgba(255,255,255,0.08);display:none;
      color:#cfe8ff;box-shadow:0 8px 24px rgba(2,6,23,0.7);z-index:1000;min-width:200px}
    #toast.show{display:block;animation:toastIn .3s ease}
    #toast.success{border-left:4px solid var(--success)}
    #toast.error{border-left:4px solid var(--danger)}
    @keyframes toastIn{from{transform:translateY(-10px);opacity:0}to{transform:translateY(0);opacity:1}}

    .section-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;
      padding-bottom:12px;border-bottom:1px solid rgba(255,255,255,0.05)}
    .muted{color:var(--muted);font-size:14px;line-height:1.6}
    .stack{display:flex;flex-direction:column;gap:10px}
    .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    .hidden{display:none}
    .text-center{text-align:center}
    .mb-2{margin-bottom:12px}
    
    .expiry-warning{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);
      padding:12px;border-radius:8px;margin-top:12px;color:#fca5a5}
    .expiry-info{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);
      padding:12px;border-radius:8px;margin-top:12px;color:#86efac}

    @media (max-width: 768px) {
      body{padding:16px}
      .container{padding:0}
      h1{font-size:24px}
      .stats{grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
      .info-grid{grid-template-columns:1fr}
      .btn{padding:9px 12px;font-size:13px}
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 VLESS Configuration Panel</h1>
    <p class="lead">Manage your proxy configuration, view subscription links, and monitor usage statistics.</p>

    <div class="stats">
      <div class="stat ${isUserExpired ? 'status-expired' : 'status-active'}">
        <div class="val" id="status-badge">${isUserExpired ? 'Expired' : 'Active'}</div>
        <div class="lbl">Account Status</div>
      </div>
      <div class="stat">
        <div class="val" id="usage-display">${formatBytes(userData.traffic_used || 0)}</div>
        <div class="lbl">Data Used</div>
      </div>
      <div class="stat ${usagePercentage > 80 ? 'status-warning' : ''}">
        <div class="val">${userData.traffic_limit && userData.traffic_limit > 0 ? formatBytes(userData.traffic_limit) : 'Unlimited'}</div>
        <div class="lbl">Data Limit</div>
      </div>
      <div class="stat">
        <div class="val" id="expiry-countdown">—</div>
        <div class="lbl">Time Remaining</div>
      </div>
    </div>

    ${userData.traffic_limit && userData.traffic_limit > 0 ? 
    `<div class="card">
      <div class="section-title">
        <h2>📊 Usage Statistics</h2>
        <!-- [FIX 6] Applied .toFixed(2) here for display -->
        <span class="muted">${usagePercentage.toFixed(2)}% Used</span>
      </div>
      <div class="progress-bar">
        <!-- [FIX 5] Applied .toFixed(2) here for display -->
        <div class="progress-fill ${usagePercentage > 80 ? 'high' : usagePercentage > 50 ? 'medium' : 'low'}" 
             style="width: ${usagePercentage.toFixed(2)}%"></div>
      </div>
      <p class="muted text-center mb-2">${formatBytes(userData.traffic_used || 0)} of ${formatBytes(userData.traffic_limit)} used</p>
    </div>`
    : ''}

    ${expirationDateTime ? 
    `<div class="card">
      <div class="section-title">
        <h2>⏰ Expiration Information</h2>
      </div>
      <div id="expiration-display" data-expiry="${expirationDateTime}">
        <p class="muted" id="expiry-local">Loading expiration time...</p>
        <p class="muted" id="expiry-utc" style="font-size:13px;margin-top:4px"></p>
      </div>
      ${isUserExpired ? 
      `<div class="expiry-warning">
        ⚠️ Your account has expired. Please contact your administrator to renew access.
      </div>`
      : 
      `<div class="expiry-info">
        ✓ Your account is currently active and working normally.
      </div>`
      }
    </div>`
    : ''}

    <div class="grid">
      <div>
        <div class="card">
          <div class="section-title">
            <h2>🌐 Network Information</h2>
            <button class="btn ghost small" id="btn-refresh-ip">Refresh</button>
          </div>
          <p class="muted">Connection details and IP information for your proxy server and current location.</p>
          <div class="info-grid">
            <div class="info-item">
              <span class="label">Proxy Host</span>
              <span class="value" id="proxy-host">${proxyAddress || hostName}</span>
            </div>
            <div class="info-item">
              <span class="label">Proxy IP</span>
              <span class="value detecting" id="proxy-ip">Detecting...</span>
            </div>
            <div class="info-item">
              <span class="label">Proxy Location</span>
              <span class="value detecting" id="proxy-location">Detecting...</span>
            </div>
            <div class="info-item">
              <span class="label">Your IP</span>
              <span class="value detecting" id="client-ip">Detecting...</span>
            </div>
            <div class="info-item">
              <span class="label">Your Location</span>
              <span class="value detecting" id="client-location">Detecting...</span>
            </div>
            <div class="info-item">
              <span class="label">Your ISP</span>
              <span class="value detecting" id="client-isp">Detecting...</span>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="section-title">
            <h2>📱 Subscription Links</h2>
          </div>
          <p class="muted">Copy subscription URLs or import directly into your VPN client application.</p>

          <div class="stack">
            <div>
              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2)">Xray / V2Ray Subscription</h3>
              <div class="buttons">
                <button class="btn primary" id="copy-xray-sub">📋 Copy Xray Link</button>
                <button class="btn ghost" id="show-xray-config">View Config</button>
                <button class="btn ghost" id="qr-xray-sub-btn">QR Code</button>
              </div>
              <pre class="config hidden" id="xray-config">${escapeHTML(singleXrayConfig)}</pre>
            </div>

            <div>
              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2)">Sing-Box / Clash Subscription</h3>
              <div class="buttons">
                <button class="btn primary" id="copy-sb-sub">📋 Copy Singbox Link</button>
                <button class="btn ghost" id="show-sb-config">View Config</button>
                <button class="btn ghost" id="qr-sb-sub-btn">QR Code</button>
              </div>
              <pre class="config hidden" id="sb-config">${escapeHTML(singleSingboxConfig)}</pre>
            </div>

            <div>
              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2)">Quick Import</h3>
              <div class="buttons">
                <a href="${clientUrls.universalAndroid}" rel="noopener noreferrer" class="btn ghost">📱 Android (V2rayNG)</a>
                <a href="${clientUrls.shadowrocket}" rel="noopener noreferrer" class="btn ghost">🍎 iOS (Shadowrocket)</a>
                <a href="${clientUrls.streisand}" rel="noopener noreferrer" class="btn ghost">🍎 iOS Streisand</a>
                <a href="${clientUrls.karing}" rel="noopener noreferrer" class="btn ghost">🔧 Android/iOS Karing</a>
              </div>
            </div>
          </div>
        </div>
      </div>

      <aside>
        <div class="card">
          <h2>QR Code Scanner</h2>
          <p class="muted mb-2">Scan with your mobile device to quickly import configuration.</p>
          <div id="qr-display" class="text-center">
            <p class="muted">Click any "QR Code" button to generate a scannable code.</p>
          </div>
          <div class="buttons" style="justify-content:center;margin-top:16px">
            <button class="btn ghost small" id="qr-xray-config-btn">Xray Config QR</button>
            <button class="btn ghost small" id="qr-sb-config-btn">Singbox Config QR</button>
          </div>
        </div>

        <div class="card">
          <h2>👤 Account Details</h2>
          <div class="info-item" style="margin-top:12px">
            <span class="label">User UUID</span>
            <span class="value" style="font-family:var(--mono);font-size:12px;word-break:break-all">${userID}</span>
          </div>
          <div class="info-item" style="margin-top:12px">
            <span class="label">Created Date</span>
            <span class="value">${new Date(userData.created_at).toLocaleDateString()}</span>
          </div>
          ${userData.notes ? 
          `<div class="info-item" style="margin-top:12px">
            <span class="label">Notes</span>
            <span class="value">${escapeHTML(userData.notes)}</span>
          </div>`
          : ''}
        </div>

        <div class="card">
          <h2>💾 Export Configuration</h2>
          <p class="muted mb-2">Download configuration file for manual import or backup purposes.</p>
          <div class="buttons">
            <button class="btn primary small" id="download-xray">Download Xray</button>
            <button class="btn primary small" id="download-sb">Download Singbox</button>
          </div>
        </div>
      </aside>
    </div>

    <div class="card">
      <p class="muted text-center" style="margin:0">
        🔒 This is your personal configuration panel. Keep your subscription links private and secure.
        <br>For support or questions, contact your service administrator.
      </p>
    </div>

    <div id="toast"></div>
  </div>

  <script nonce="CSP_NONCE_PLACEHOLDER">
    window.CONFIG = {
      uuid: "${userID}",
      host: "${hostName}",
      proxyAddress: "${proxyAddress || hostName}",
      subXrayUrl: "${subXrayUrl}",
      subSbUrl: "${subSbUrl}",
      singleXrayConfig: ${JSON.stringify(singleXrayConfig)},
      singleSingboxConfig: ${JSON.stringify(singleSingboxConfig)},
      expirationDateTime: ${expirationDateTime ? `"${expirationDateTime}"` : 'null'},
      isExpired: ${isUserExpired},
      clientUrls: ${JSON.stringify(clientUrls)}
    };

    function generateQRCode(text) {
      const qrDisplay = document.getElementById('qr-display');
      const size = 280;
      const encodedText = encodeURIComponent(text);
     
      qrDisplay.innerHTML = \`
        <div class="qr-container">
          <img src="https://api.qrserver.com/v1/create-qr-code/?size=\${size}x\${size}&data=\${encodedText}&format=png&ecc=M" 
               alt="QR Code" 
               style="width:\${size}px;height:\${size}px;display:block;border-radius:8px"
               onload="this.style.opacity=1;showToast('QR code generated successfully', 'success')"
               onerror="this.parentElement.innerHTML='<p class=muted style=color:var(--danger)>QR generation failed. Please copy the link manually.</p>'"
               style="opacity:0;transition:opacity 0.3s" />
        </div>
      \`;
    }

    function showToast(message, type = 'success') {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.className = type;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 3500);
    }

    async function copyToClipboard(text, button) {
      try {
        await navigator.clipboard.writeText(text);
        const originalText = button.innerHTML;
        button.innerHTML = '✓ Copied!';
        button.disabled = true;
        setTimeout(() => {
          button.innerHTML = originalText;
          button.disabled = false;
        }, 2000);
        showToast('Copied to clipboard successfully!', 'success');
      } catch (error) {
        showToast('Failed to copy to clipboard', 'error');
        console.error('Copy error:', error);
      }
    }

    function downloadConfig(content, filename) {
      const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      showToast(\`Configuration downloaded: \${filename}\`, 'success');
    }

    async function fetchIPInfo() {
      const displayElement = (id, value, isFinal = false) => {
        const el = document.getElementById(id);
        if (!el) return;
        
        el.innerHTML = value || 'Unavailable';
        if (isFinal) {
          el.classList.remove('detecting');
        }
      };

      async function fetchWithTimeout(url, timeout = 6000) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        try {
          const response = await fetch(url, { 
            signal: controller.signal,
            cache: 'no-store'
          });
          clearTimeout(timeoutId);
          
          if (!response.ok) throw new Error(\`HTTP \${response.status}\`);
          return response;
        } catch (error) {
          clearTimeout(timeoutId);
          throw error;
        }
      }

      const clientIPAPIs = [
        { 
          url: 'https://api.ipify.org?format=json', 
          parse: async (r) => {
            const data = await r.json();
            return data.ip;
          }
        },
        {
          url: 'https://api.my-ip.io/v2/ip.json',
          parse: async (r) => {
            const data = await r.json();
            return data.ip;
          }
        },
        {
          url: 'https://ifconfig.me/ip',
          parse: async (r) => await r.text()
        },
        {
          url: 'https://icanhazip.com',
          parse: async (r) => (await r.text()).trim()
        },
        {
          url: 'https://ipinfo.io/json',
          parse: async (r) => {
            const data = await r.json();
            return data.ip;
          }
        }
      ];

      let clientIP = null;
      for (const api of clientIPAPIs) {
        try {
          const response = await fetchWithTimeout(api.url);
          clientIP = await api.parse(response);
          if (clientIP && clientIP.trim()) {
            clientIP = clientIP.trim();
            displayElement('client-ip', clientIP, true);
            break;
          }
        } catch (error) {
          console.log(\`Client IP API failed (\${api.url}): \${error.message}\`);
        }
      }

      if (!clientIP) {
        displayElement('client-ip', 'Detection failed', true);
      }

      const clientGeoAPIs = [
        {
          url: clientIP ? \`https://ipapi.co/\${clientIP}/json/\` : 'https://ipapi.co/json/',
          parse: async (r) => {
            const data = await r.json();
            return {
              city: data.city || '',
              country: data.country_name || '',
              isp: data.org || ''
            };
          }
        },
        {
          url: clientIP ? \`https://ip-api.com/json/\${clientIP}\` : 'https://ip-api.com/json/',
          parse: async (r) => {
            const data = await r.json();
            if (data.status === 'fail') throw new Error(data.message);
            return {
              city: data.city || '',
              country: data.country || '',
              isp: data.isp || ''
            };
          }
        },
        {
          url: clientIP ? \`https://ipinfo.io/\${clientIP}/json\` : 'https://ipinfo.io/json',
          parse: async (r) => {
            const data = await r.json();
            return {
              city: data.city || '',
              country: data.country || '',
              isp: data.org || ''
            };
          }
        }
      ];

      let clientGeo = null;
      for (const api of clientGeoAPIs) {
        try {
          const response = await fetchWithTimeout(api.url);
          clientGeo = await api.parse(response);
          if (clientGeo && (clientGeo.city || clientGeo.country)) {
            const location = [clientGeo.city, clientGeo.country].filter(Boolean).join(', ') || 'Unknown';
            displayElement('client-location', location, true);
            displayElement('client-isp', clientGeo.isp || 'Unknown', true);
            break;
          }
        } catch (error) {
          console.log(\`Client Geo API failed (\${api.url}): \${error.message}\`);
        }
      }

      if (!clientGeo) {
        displayElement('client-location', 'Detection failed', true);
        displayElement('client-isp', 'Detection failed', true);
      }

      const proxyHost = window.CONFIG.proxyAddress.split(':')[0];
      let proxyIP = proxyHost;
      
      const ipv4Regex = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/;
      const ipv6Regex = /^\\[?[0-9a-fA-F:]+\\]?$/;
      
      if (!ipv4Regex.test(proxyHost) && !ipv6Regex.test(proxyHost)) {
        const dnsAPIs = [
          {
            url: \`https://dns.google/resolve?name=\${encodeURIComponent(proxyHost)}&type=A\`,
            parse: async (r) => {
              const data = await r.json();
              const answer = data.Answer?.find(a => a.type === 1);
              return answer?.data;
            }
          },
          {
            url: \`https://cloudflare-dns.com/dns-query?name=\${encodeURIComponent(proxyHost)}&type=A\`,
            parse: async (r) => {
              const data = await r.json();
              const answer = data.Answer?.find(a => a.type === 1);
              return answer?.data;
            }
          }
        ];

        for (const api of dnsAPIs) {
          try {
            const response = await fetchWithTimeout(api.url, {
                headers: { 'accept': 'application/dns-json' },
            });
            const resolvedIP = await api.parse(response);
            if (resolvedIP) {
              proxyIP = resolvedIP;
              break;
            }
          } catch (error) {
            console.log(\`DNS resolution failed (\${api.url}): \${error.message}\`);
          }
        }
      }
      
      displayElement('proxy-ip', proxyIP, true);

      const proxyGeoAPIs = [
        {
          url: \`https://ip-api.com/json/\${proxyIP}\`,
          parse: async (r) => {
            const data = await r.json();
            if (data.status === 'fail') throw new Error(data.message);
            return {
              city: data.city || '',
              country: data.country || ''
            };
          }
        },
        {
          url: \`https://ipapi.co/\${proxyIP}/json/\`,
          parse: async (r) => {
            const data = await r.json();
            return {
              city: data.city || '',
              country: data.country_name || ''
            };
          }
        },
        {
          url: \`https://ipinfo.io/\${proxyIP}/json\`,
          parse: async (r) => {
            const data = await r.json();
            return {
              city: data.city || '',
              country: data.country || ''
            };
          }
        }
      ];

      let proxyGeo = null;
      for (const api of proxyGeoAPIs) {
        try {
          const response = await fetchWithTimeout(api.url);
          proxyGeo = await api.parse(response);
          if (proxyGeo && (proxyGeo.city || proxyGeo.country)) {
            const location = [proxyGeo.city, proxyGeo.country].filter(Boolean).join(', ') || 'Unknown';
            displayElement('proxy-location', location, true);
            break;
          }
        } catch (error) {
          console.log(\`Proxy Geo API failed (\${api.url}): \${error.message}\`);
        }
      }

      if (!proxyGeo) {
        displayElement('proxy-location', 'Detection failed', true);
      }
    }

    function updateExpirationDisplay() {
      if (!window.CONFIG.expirationDateTime) return;
      
      const expiryDate = new Date(window.CONFIG.expirationDateTime);
      const now = new Date();
      const diffMs = expiryDate - now;
      const diffSeconds = Math.floor(diffMs / 1000);
      
      const countdownEl = document.getElementById('expiry-countdown');
      const localEl = document.getElementById('expiry-local');
      const utcEl = document.getElementById('expiry-utc');
      
      if (diffSeconds < 0) {
        countdownEl.textContent = 'Expired';
        countdownEl.parentElement.classList.add('status-expired');
        return;
      }
      
      const days = Math.floor(diffSeconds / 86400);
      const hours = Math.floor((diffSeconds % 86400) / 3600);
      const minutes = Math.floor((diffSeconds % 3600) / 60);
      
      if (days > 0) {
        countdownEl.textContent = \`\${days}d \${hours}h\`;
      } else if (hours > 0) {
        countdownEl.textContent = \`\${hours}h \${minutes}m\`;
      } else {
        countdownEl.textContent = \`\${minutes}m\`;
      }
      
      if (localEl) {
        localEl.textContent = \`Expires: \${expiryDate.toLocaleString()}\`;
      }
      if (utcEl) {
        utcEl.textContent = \`UTC: \${expiryDate.toISOString().replace('T', ' ').substring(0, 19)}\`;
      }
    }

    document.addEventListener('DOMContentLoaded', () => {
      document.getElementById('copy-xray-sub').addEventListener('click', function() {
        copyToClipboard(window.CONFIG.subXrayUrl, this);
      });
      
      document.getElementById('copy-sb-sub').addEventListener('click', function() {
        copyToClipboard(window.CONFIG.subSbUrl, this);
      });
      
      document.getElementById('show-xray-config').addEventListener('click', () => {
        document.getElementById('xray-config').classList.toggle('hidden');
      });
      
      document.getElementById('show-sb-config').addEventListener('click', () => {
        document.getElementById('sb-config').classList.toggle('hidden');
      });
      
      document.getElementById('qr-xray-sub-btn').addEventListener('click', () => {
        generateQRCode(window.CONFIG.subXrayUrl);
      });
      
      document.getElementById('qr-sb-sub-btn').addEventListener('click', () => {
        generateQRCode(window.CONFIG.subSbUrl);
      });
      
      document.getElementById('qr-xray-config-btn').addEventListener('click', () => {
        generateQRCode(window.CONFIG.singleXrayConfig);
      });
      
      document.getElementById('qr-sb-config-btn').addEventListener('click', () => {
        generateQRCode(window.CONFIG.singleSingboxConfig);
      });
      
      document.getElementById('download-xray').addEventListener('click', () => {
        downloadConfig(window.CONFIG.singleXrayConfig, 'xray-vless-config.txt');
      });
      
      document.getElementById('download-sb').addEventListener('click', () => {
        downloadConfig(window.CONFIG.singleSingboxConfig, 'singbox-vless-config.txt');
      });
      
      document.getElementById('btn-refresh-ip').addEventListener('click', () => {
        showToast('Refreshing network information...', 'success');
        const detectingHTML = '<span class="value detecting">Detecting...</span>';
        document.getElementById('proxy-ip').className = 'value detecting';
        document.getElementById('proxy-ip').textContent = 'Detecting...';
        document.getElementById('proxy-location').className = 'value detecting';
        document.getElementById('proxy-location').textContent = 'Detecting...';
        document.getElementById('client-ip').className = 'value detecting';
        document.getElementById('client-ip').textContent = 'Detecting...';
        document.getElementById('client-location').className = 'value detecting';
        document.getElementById('client-location').textContent = 'Detecting...';
        document.getElementById('client-isp').className = 'value detecting';
        document.getElementById('client-isp').textContent = 'Detecting...';
        fetchIPInfo();
      });
      
      fetchIPInfo();
      updateExpirationDisplay();
      
      setInterval(updateExpirationDisplay, 60000);
    });
  </script>
</body>
</html>`;
    const nonce = generateNonce();
    const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    addSecurityHeaders(headers, nonce, {
        img: 'api.qrserver.com',
        connect: '*.ip-api.com *.ipapi.co *.ipify.org *.my-ip.io ifconfig.me icanhazip.com *.ipinfo.io dns.google cloudflare-dns.com'
    });
    let finalHtml = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
    return new Response(finalHtml, { headers });
}

// ============================================================================
// VLESS PROTOCOL HANDLERS
// ============================================================================

async function ProtocolOverWSHandler(request, config, env, ctx) {
  const clientIp = request.headers.get('CF-Connecting-IP');
  if (await isSuspiciousIP(clientIp, config.scamalytics, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
    return new Response('Access denied', { status: 403 });
  }

  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = '';
  let portWithRandomLog = '';
  let sessionUsage = 0;
  let userUUID = '';
  let udpStreamWriter = null;

  const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');

  const deferredUsageUpdate = () => {
    if (sessionUsage > 0 && userUUID) {
      const usageToUpdate = sessionUsage;
      const uuidToUpdate = userUUID;
      
      sessionUsage = 0;
      
      ctx.waitUntil(
        updateUsage(env, uuidToUpdate, usageToUpdate, ctx)
          .catch(err => console.error(`Deferred usage update failed for ${uuidToUpdate}:`, err))
      );
    }
  };

  const updateInterval = setInterval(deferredUsageUpdate, 10000);

  const finalCleanup = () => {
    clearInterval(updateInterval);
    deferredUsageUpdate();
  };

  webSocket.addEventListener('close', finalCleanup, { once: true });
  webSocket.addEventListener('error', finalCleanup, { once: true });

  const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
  const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWrapper = { value: null };

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          sessionUsage += chunk.byteLength;

          if (udpStreamWriter) {
            return udpStreamWriter.write(chunk);
          }

          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            user,
            hasError,
            message,
            addressType,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            ProtocolVersion = new Uint8Array([0, 0]),
            isUDP,
          } = await ProcessProtocolHeader(chunk, env, ctx);

          if (hasError) {
            controller.error(new Error('Authentication failed')); // Hidden error
            return;
          }
          
          if (!user) {
            controller.error(new Error('Authentication failed')); // Hidden error
            return;
          }

          userUUID = user.uuid;

          if (isExpired(user.expiration_date, user.expiration_time)) {
            controller.error(new Error('Authentication failed')); // Hidden error
            return;
          }

          if (user.traffic_limit && user.traffic_limit > 0) {
            const totalUsage = (user.traffic_used || 0) + sessionUsage;
            if (totalUsage >= user.traffic_limit) {
              controller.error(new Error('Authentication failed')); // Hidden error
              return;
            }
          }

          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'}`;
          const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isUDP) {
            if (portRemote === 53) {
              const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log, (bytes) => {
                sessionUsage += bytes;
              });
              udpStreamWriter = dnsPipeline.write;
              await udpStreamWriter(rawClientData);
            } else {
              controller.error(new Error('Authentication failed')); // Hidden error
            }
            return;
          }

          HandleTCPOutBound(
            remoteSocketWrapper,
            addressType,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            log,
            config,
            (bytes) => { sessionUsage += bytes; }
          );
        },
        close() {
          log('readableWebSocketStream closed');
          finalCleanup();
        },
        abort(err) {
          log('readableWebSocketStream aborted', err);
          finalCleanup();
        },
      }),
    )
    .catch(err => {
      console.error('Pipeline failed:', err.stack || err);
      safeCloseWebSocket(webSocket);
      finalCleanup();
    });

  return new Response(null, { status: 101, webSocket: client });
}

async function ProcessProtocolHeader(protocolBuffer, env, ctx) {
  if (protocolBuffer.byteLength < 24) {
    return { hasError: true, message: 'invalid data' };
  }
  
  const dataView = new DataView(protocolBuffer.buffer || protocolBuffer);
  const version = dataView.getUint8(0);

  let uuid;
  try {
    uuid = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
  } catch (e) {
    return { hasError: true, message: 'invalid UUID format' };
  }

  const userData = await getUserData(env, uuid, ctx);
  if (!userData) {
    return { hasError: true, message: 'invalid user' };
  }

  const payloadStart = 17;
  if (protocolBuffer.byteLength < payloadStart + 1) {
    return { hasError: true, message: 'invalid data length' };
  }

  const optLength = dataView.getUint8(payloadStart);
  const commandIndex = payloadStart + 1 + optLength;
  
  if (protocolBuffer.byteLength < commandIndex + 1) {
    return { hasError: true, message: 'invalid data length (command)' };
  }
  
  const command = dataView.getUint8(commandIndex);
  if (command !== 1 && command !== 2) {
    return { hasError: true, message: `command ${command} is not supported` };
  }

  const portIndex = commandIndex + 1;
  if (protocolBuffer.byteLength < portIndex + 2) {
    return { hasError: true, message: 'invalid data length (port)' };
  }
  
  const portRemote = dataView.getUint16(portIndex, false);

  const addressTypeIndex = portIndex + 2;
  if (protocolBuffer.byteLength < addressTypeIndex + 1) {
    return { hasError: true, message: 'invalid data length (address type)' };
  }
  
  const addressType = dataView.getUint8(addressTypeIndex);

  let addressValue, addressLength, addressValueIndex;

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValueIndex = addressTypeIndex + 1;
      if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
        return { hasError: true, message: 'invalid data length (ipv4)' };
      }
      addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
      
    case 2:
      if (protocolBuffer.byteLength < addressTypeIndex + 2) {
        return { hasError: true, message: 'invalid data length (domain length)' };
      }
      addressLength = dataView.getUint8(addressTypeIndex + 1);
      addressValueIndex = addressTypeIndex + 2;
      if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
        return { hasError: true, message: 'invalid data length (domain)' };
      }
      addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
      
    case 3:
      addressLength = 16;
      addressValueIndex = addressTypeIndex + 1;
      if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
        return { hasError: true, message: 'invalid data length (ipv6)' };
      }
      addressValue = Array.from({ length: 8 }, (_, i) => 
        dataView.getUint16(addressValueIndex + i * 2, false).toString(16)
      ).join(':');
      break;
      
    default:
      return { hasError: true, message: `invalid addressType: ${addressType}` };
  }

  const rawDataIndex = addressValueIndex + addressLength;
  if (protocolBuffer.byteLength < rawDataIndex) {
    return { hasError: true, message: 'invalid data length (raw data)' };
  }

  return {
    user: userData,
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex,
    ProtocolVersion: new Uint8Array([version]),
    isUDP: command === 2,
  };
}

async function HandleTCPOutBound(
  remoteSocket,
  addressType,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  protocolResponseHeader,
  log,
  config,
  trafficCallback
) {
  async function connectAndWrite(address, port, socks = false) {
    let tcpSocket;
    if (config.socks5Relay) {
      tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
    } else {
      tcpSocket = socks
        ? await socks5Connect(addressType, address, port, log, config.parsedSocks5Address)
        : connect({ hostname: address, port: port });
    }
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = config.enableSocks
      ? await connectAndWrite(addressRemote, portRemote, true)
      : await connectAndWrite(
          config.proxyIP || addressRemote,
          config.proxyPort || portRemote,
          false,
        );

    tcpSocket.closed
      .catch(error => {
        console.log('retry tcpSocket closed error', error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log, trafficCallback);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback);
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => controller.enqueue(event.data));
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer has error');
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(_controller) { },
    cancel(reason) {
      log(`ReadableStream was canceled, due to ${reason}`);
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback) {
  let hasIncomingData = false;
  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN)
            throw new Error('WebSocket is not open');
          hasIncomingData = true;
          
          if (trafficCallback) {
            trafficCallback(chunk.byteLength);
          }
          
          const dataToSend = protocolResponseHeader
            ? await new Blob([protocolResponseHeader, chunk]).arrayBuffer()
            : chunk;
          webSocket.send(dataToSend);
          protocolResponseHeader = null;
        },
        close() {
          log(`Remote connection readable closed. Had incoming data: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error('Remote connection readable aborted:', reason);
        },
      }),
    );
  } catch (error) {
    console.error('RemoteSocketToWS error:', error.stack || error);
    safeCloseWebSocket(webSocket);
  }
  if (!hasIncomingData && retry) {
    log('No incoming data, retrying');
    try {
        await retry();
    } catch(e) {
        console.error('Retry failed:', e);
    }
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    const binaryStr = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
    const buffer = new ArrayBuffer(binaryStr.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryStr.length; i++) {
      view[i] = binaryStr.charCodeAt(i);
    }
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (
      socket.readyState === CONST.WS_READY_STATE_OPEN ||
      socket.readyState === CONST.WS_READY_STATE_CLOSING
    ) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error:', error);
  }
}

async function createDnsPipeline(webSocket, vlessResponseHeader, log, trafficCallback) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        if (index + 2 > chunk.byteLength) break;
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        if (index + 2 + udpPacketLength > chunk.byteLength) break;
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            const resp = await fetch('https://1.1.1.1/dns-query', {
              method: 'POST',
              headers: { 'content-type': 'application/dns-message' },
              body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              log(`DNS query successful, length: ${udpSize}`);
              let responseChunk;
              if (isHeaderSent) {
                responseChunk = await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer();
              } else {
                responseChunk = await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                isHeaderSent = true;
              }
              if (trafficCallback) {
                trafficCallback(responseChunk.byteLength);
              }
              webSocket.send(responseChunk);
            }
          } catch (error) {
            log('DNS query error: ' + error);
          }
        },
      }),
    )
    .catch(e => {
      log('DNS stream error: ' + e);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write: (chunk) => writer.write(chunk),
  };
}

async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Address) {
  const { username, password, hostname, port } = parsedSocks5Address;
  const socket = connect({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();

  await writer.write(new Uint8Array([5, 2, 0, 2]));
  let res = (await reader.read()).value;
  if (!res || res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 handshake failed');

  if (res[1] === 0x02) {
    if (!username || !password) throw new Error('SOCKS5 credentials required');
    const authRequest = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (!res || res[0] !== 0x01 || res[1] !== 0x00) throw new Error('SOCKS5 authentication failed');
  }

  let dstAddr;
  switch (addressType) {
    case 1:
      dstAddr = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
      break;
    case 2:
      dstAddr = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
      break;
    case 3:
      dstAddr = new Uint8Array([4, ...addressRemote.split(':').flatMap(x => {
        if (x === '') return [0,0]; // Handle empty parts in IPv6 from compression
        const part = x.padStart(4, '0');
        return [parseInt(part.slice(0, 2), 16), parseInt(part.slice(2), 16)];
      })]);
      break;
    default:
      throw new Error(`Invalid address type: ${addressType}`);
  }

  const socksRequest = new Uint8Array([5, 1, 0, ...dstAddr, portRemote >> 8, portRemote & 0xff]);
  await writer.write(socksRequest);
  res = (await reader.read()).value;
  if (!res || res[1] !== 0x00) throw new Error(`SOCKS5 connection failed with code ${res[1]}`);

  writer.releaseLock();
  reader.releaseLock();
  return socket;
}

function socks5AddressParser(address) {
  if (!address || typeof address !== 'string') {
    throw new Error('Invalid SOCKS5 address format');
  }
  const [authPart, hostPart] = address.includes('@') ? address.split('@') : [null, address];
  const lastColonIndex = hostPart.lastIndexOf(':');

  if (lastColonIndex === -1) {
    throw new Error('Invalid SOCKS5 address: missing port');
  }
  
  const hostname = hostPart.substring(0, lastColonIndex);
  const portStr = hostPart.substring(lastColonIndex + 1);
  const port = parseInt(portStr, 10);
  
  if (!hostname || isNaN(port)) {
    throw new Error('Invalid SOCKS5 address');
  }

  let username, password;
  if (authPart) {
    [username, password] = authPart.split(':');
  }
  
  return { username, password, hostname, port };
}

// ============================================================================
// MAIN FETCH HANDLER (WITH SECURITY HEADERS)
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    let cfg;
    
    try {
      cfg = await Config.fromEnv(env);
    } catch (err) {
      console.error(`Configuration Error: ${err.message}`);
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response(`Configuration Error: ${err.message}`, { status: 503, headers });
    }

    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP');

    // ---[ HARDENED: Handle Admin Requests First ]---
    // All admin-related traffic is now handled by this function,
    // which includes secret path, IP whitelist, and rate limiting.
    
    // Get the customizable admin prefix, default to 'admin'
    const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
    
    if (url.pathname.startsWith(`/${adminPrefix}/`)) {
      return await handleAdminRequest(request, env, ctx, adminPrefix);
    }

    if (url.pathname === '/health') {
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('OK', { status: 200, headers });
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader?.toLowerCase() === 'websocket') {
      if (!env.DB || !env.USER_KV) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service not configured properly', { status: 503, headers });
      }
      
      const requestConfig = {
        userID: cfg.userID,
        proxyIP: cfg.proxyIP,
        proxyPort: cfg.proxyPort,
        socks5Address: cfg.socks5.address,
        socks5Relay: cfg.socks5.relayMode,
        enableSocks: cfg.socks5.enabled,
        parsedSocks5Address: cfg.socks5.enabled ? socks5AddressParser(cfg.socks5.address) : {},
        scamalytics: cfg.scamalytics,
      };
      
      const wsResponse = await ProtocolOverWSHandler(request, requestConfig, env, ctx);
      
      // Add security headers to the WebSocket handshake response
      const headers = new Headers(wsResponse.headers);
      addSecurityHeaders(headers, null, {});
      
      // Note: wsResponse.webSocket is a special property that needs to be passed to the Response constructor.
      return new Response(wsResponse.body, { status: wsResponse.status, webSocket: wsResponse.webSocket, headers });
    }

    const handleSubscription = async (core) => {
      const rateLimitKey = `user_path_rate:${clientIp}`;
      if (await checkRateLimit(env.USER_KV, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Rate limit exceeded', { status: 429, headers });
      }

      const uuid = url.pathname.substring(`/${core}/`.length);
      if (!isValidUUID(uuid)) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Invalid UUID', { status: 400, headers });
      }
      
      const userData = await getUserData(env, uuid, ctx);
      if (!userData) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers }); // Hidden error
      }
      
      if (isExpired(userData.expiration_date, userData.expiration_time)) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers }); // Hidden error
      }
      
      if (userData.traffic_limit && userData.traffic_limit > 0 && 
          (userData.traffic_used || 0) >= userData.traffic_limit) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers }); // Hidden error
      }
      
      // handleIpSubscription now adds its own security headers
      return await handleIpSubscription(core, uuid, url.hostname);
    };

    if (url.pathname.startsWith('/xray/')) {
      return await handleSubscription('xray');
    }
    
    if (url.pathname.startsWith('/sb/')) {
      return await handleSubscription('sb');
    }

    const path = url.pathname.slice(1);
    if (isValidUUID(path)) {
      const rateLimitKey = `user_path_rate:${clientIp}`;
      if (await checkRateLimit(env.USER_KV, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Rate limit exceeded', { status: 429, headers });
      }

      const userData = await getUserData(env, path, ctx);
      if (!userData) {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Authentication failed', { status: 403, headers }); // Hidden error
      }
      
      // handleUserPanel now adds its own security headers (including CSP/nonce)
      return handleUserPanel(path, url.hostname, cfg.proxyAddress, userData);
    }

    if (env.ROOT_PROXY_URL) {
      try {
        const proxyUrl = new URL(env.ROOT_PROXY_URL);
        const targetUrl = new URL(request.url);
        
        targetUrl.hostname = proxyUrl.hostname;
        targetUrl.protocol = proxyUrl.protocol;
        targetUrl.port = proxyUrl.port;
        
        const newRequest = new Request(targetUrl, request);
        newRequest.headers.set('Host', proxyUrl.hostname);
        newRequest.headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP'));
        newRequest.headers.set('X-Forwarded-Proto', 'httpsS');
        
        const response = await fetch(newRequest);
        const mutableHeaders = new Headers(response.headers);
        
        // Add security headers, but respect proxy's CSP/XFO if they exist
        if (!mutableHeaders.has('Content-Security-Policy')) {
          mutableHeaders.set('Content-Security-Policy', "default-src 'self'; object-src 'none'; frame-ancestors 'none';");
        }
        if (!mutableHeaders.has('X-Frame-Options')) {
          mutableHeaders.set('X-Frame-Options', 'SAMEORIGIN');
        }
        mutableHeaders.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
        mutableHeaders.set('X-Content-Type-Options', 'nosniff');
        mutableHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
        mutableHeaders.set('alt-svc', 'h3=":443"; ma=0');
        
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: mutableHeaders
        });
      } catch (e) {
        console.error(`Reverse Proxy Error: ${e.message}`);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response(`Proxy configuration error: ${e.message}`, { status: 502, headers });
      }
    }

    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers });
  },
};

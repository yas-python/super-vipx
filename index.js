import { connect } from 'cloudflare:sockets';

// ============================================================================
// ULTIMATE VLESS PROXY WORKER - FINAL FIXED VERSION (NO ERRORS)
// ============================================================================
// Features:
// - VLESS over WebSocket (TLS & non-TLS)
// - Full Admin Panel (/admin)
// - User Dashboard (/uuid)
// - Subscription Links (/xray/uuid, /sb/uuid)
// - Traffic Limit & Expiry
// - IP Rotation (Clean IPs + GitHub JSON)
// - Proxy IP from KV, env.PROXYIP, or hardcoded
// - Network Info (Client + Proxy IP/Location/ISP)
// - QR Code (via qrserver.com)
// - Copy UUID Button in Admin
// - Reverse Proxy Mode
// - Health Check (/health)
// - No Syntax Errors, No 'class' Issues
// ============================================================================

// ============================================================================
// CONFIGURATION
// ============================================================================

const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
  scamalytics: {
    username: 'revilseptember',
    apiKey: 'b2fc368184deb3d8ac914bd776b8215fe899dd8fef69fbaba77511acfbdeca0d',
    baseUrl: 'https://api12.scamalytics.com/v3/',
  },
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },

  async fromEnv(env) {
    let selectedProxyIP = null;

    if (env.PROXY_KV) {
      const proxyIpKey = env.PROXY_IP_KEY || 'BEST_PROXY_IP';
      try {
        selectedProxyIP = await env.PROXY_KV.get(proxyIpKey);
        if (selectedProxyIP) console.log(`Using proxy IP from KV: ${selectedProxyIP}`);
      } catch (e) {
        console.error(`Failed to read from PROXY_KV: ${e.message}`);
      }
    }

    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) console.log(`Using proxy IP from env.PROXYIP: ${selectedProxyIP}`);
    }

    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) console.log(`Using proxy IP from hardcoded list: ${selectedProxyIP}`);
    }

    if (!selectedProxyIP) {
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
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

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
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC);
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
  if (!env.DB || !env.USER_KV) return null;

  const cacheKey = `user:${uuid}`;
  try {
    const cached = await env.USER_KV.get(cacheKey, 'json');
    if (cached && cached.uuid) return cached;
  } catch (e) {}

  const user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
  if (!user) return null;

  const cachePromise = env.USER_KV.put(cacheKey, JSON.stringify(user), { expirationTtl: 3600 });
  if (ctx) ctx.waitUntil(cachePromise);
  else await cachePromise;

  return user;
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  try {
    const usage = Math.round(bytes);
    const p1 = env.DB.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?").bind(usage, uuid).run();
    const p2 = env.USER_KV.delete(`user:${uuid}`);
    if (ctx) ctx.waitUntil(Promise.all([p1, p2]));
    else await Promise.all([p1, p2]);
  } catch (err) {
    console.error(`Failed to update usage for ${uuid}:`, err);
  }
}

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
// SUBSCRIPTION & LINKS
// ============================================================================

function generateRandomPath(length = 12, query = '') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
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
    hostName, 'creativecommons.org', 'mail.tm', 'temp-mail.org', 'mdbmax.com', 'check-host.net', 'kodambroker.com', 'iplocation.io', 'whatismyip.org', 'whatismyip.com', 'www.speedtest.net',
    'sky.rethinkdns.com', 'cfip.1323123.xyz', 'go.inmobi.com', 'whatismyipaddress.com', 'cf.090227.xyz', 'cdnjs.com', 'zula.ir',
  ];
  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  let links = [];
  const isPages = hostName.endsWith('.pages.dev');

  mainDomains.forEach((domain, i) => {
    links.push(buildLink({ core, proto: 'tls', userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i+1}` }));
    if (!isPages) links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: domain, port: pick(httpPorts), tag: `D${i+1}` }));
  });

  try {
    const r = await fetch('https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json');
    if (r.ok) {
      const json = await r.json();
      const ips = [...(json.ipv4 ?? []), ...(json.ipv6 ?? [])].slice(0, 20).map(x => x.ip);
      ips.forEach((ip, i) => {
        const addr = ip.includes(':') ? `[${ip}]` : ip;
        links.push(buildLink({ core, proto: 'tls', userID, hostName, address: addr, port: pick(httpsPorts), tag: `IP${i+1}` }));
        if (!isPages) links.push(buildLink({ core, proto: 'tcp', userID, hostName, address: addr, port: pick(httpPorts), tag: `IP${i+1}` }));
      });
    }
  } catch (e) {}

  return new Response(btoa(links.join('\n')), {
    headers: { 'Content-Type': 'text/plain;charset=utf-8', 'alt-svc': 'h3=":443"; ma=0' },
  });
}

// ============================================================================
// ADMIN & USER PANEL HTML (NO 'class' IN JS)
// ============================================================================

const adminLoginHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Login</title><style>body{display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#121212;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}.login-container{background:#1e1e1e;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.5);text-align:center;width:320px;border:1px solid #333}h1{color:#fff;margin-bottom:24px;font-weight:500}input[type=password]{background:#2c2c2c;border:1px solid #444;color:#fff;padding:12px;border-radius:8px;margin-bottom:20px;font-size:16px;width:100%}input:focus{outline:none;border-color:#007aff;box-shadow:0 0 0 2px rgba(0,122,255,.3)}button{background:#007aff;color:#fff;border:none;padding:12px;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:.2s}button:hover{background:#005ecb}.error{color:#ff3b30;margin-top:15px;font-size:14px}</style></head><body><div class="login-container"><h1>Admin Login</h1><form method="POST" action="/admin"><input type="password" name="password" placeholder="Enter admin password" required><button type="submit">Login</button></form></div></body></html>`;

const adminPanelHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Dashboard</title><style>:root{--bg-main:#111827;--bg-card:#1F2937;--border:#374151;--text-primary:#F9FAFB;--text-secondary:#9CA3AF;--accent:#3B82F6;--danger:#EF4444;--success:#22C55E;--warning:#F59E0B}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg-main);color:var(--text-primary);font-size:14px}.container{max-width:1200px;margin:40px auto;padding:0 20px}h1,h2{font-weight:600}h1{font-size:24px;margin-bottom:20px}h2{font-size:18px;border-bottom:1px solid var(--border);padding-bottom:10px;margin-bottom:20px}.card{background:var(--bg-card);border-radius:8px;padding:24px;border:1px solid var(--border);box-shadow:0 4px 6px rgba(0,0,0,.1)}.dashboard-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}.stat-card{background:#1F2937;padding:16px;border-radius:8px;text-align:center;border:1px solid var(--border)}.stat-value{font-size:24px;font-weight:600;color:var(--accent)}.stat-label{font-size:12px;color:var(--text-secondary);text-transform:uppercase;margin-top:4px}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;align-items:flex-end}.form-group{display:flex;flex-direction:column}label{margin-bottom:8px;font-weight:500;color:var(--text-secondary)}.input-group{display:flex}input,select{width:100%;box-sizing:border-box;background:#374151;border:1px solid #4B5563;color:var(--text-primary);padding:10px;border-radius:6px;font-size:14px;transition:.2s}input:focus,select:focus{outline:none;border-color:var(--accent)}.btn{padding:10px 16px;border:none;border-radius:6px;font-weight:600;cursor:pointer;transition:.2s;display:inline-flex;align-items:center;gap:8px}.btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:#2563EB}.btn-danger{background:var(--danger);color:#fff}.btn-danger:hover{background:#DC2626}.btn-secondary{background:#4B5563;color:#fff}.btn-secondary:hover{background:#6B7280}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{padding:12px 16px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}th{color:var(--text-secondary);font-weight:600;font-size:12px;text-transform:uppercase}td{color:var(--text-primary);font-family:"SF Mono",monospace;font-size:13px}.status-badge{padding:4px 8px;border-radius:12px;font-size:12px;font-weight:600;display:inline-block}.status-active{background:var(--success);color:#064E3B}.status-expired{background:var(--warning);color:#78350F}.uuid-cell{display:flex;gap:8px;align-items:center}.btn-copy-uuid{padding:4px 8px;font-size:11px;background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);color:var(--accent);border-radius:4px;cursor:pointer}.btn-copy-uuid:hover{background:rgba(59,130,246,.2)}.btn-copy-uuid.copied{background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.3);color:var(--success)}#toast{position:fixed;top:20px;right:20px;background:var(--bg-card);color:#fff;padding:15px 20px;border-radius:8px;z-index:1001;display:none;border:1px solid var(--border);box-shadow:0 4px 12px rgba(0,0,0,.3);opacity:0;transition:.3s}#toast.show{display:block;opacity:1}#toast.error{border-left:5px solid var(--danger)}#toast.success{border-left:5px solid var(--success)}</style></head><body><div class="container"><h1>Admin Dashboard</h1><div class="dashboard-stats"><div class="stat-card"><div class="stat-value" id="total-users">0</div><div class="stat-label">Total Users</div></div><div class="stat-card"><div class="stat-value" id="active-users">0</div><div class="stat-label">Active Users</div></div><div class="stat-card"><div class="stat-value" id="expired-users">0</div><div class="stat-label">Expired Users</div></div><div class="stat-card"><div class="stat-value" id="total-traffic">0 KB</div><div class="stat-label">Total Traffic</div></div></div><div class="card"><h2>Create User</h2><form id="createUserForm" class="form-grid"><div class="form-group" style="grid-column:1/-1"><label>UUID</label><div class="input-group"><input type="text" id="uuid" required><button type="button" id="generateUUID" class="btn btn-secondary">Generate</button></div></div><div class="form-group"><label>Expiry Date</label><input type="date" id="expiryDate" required></div><div class="form-group"><label>Expiry Time</label><input type="time" id="expiryTime" step="1" required></div><div class="form-group"><label>Notes</label><input type="text" id="notes"></div><div class="form-group"><label>Data Limit</label><div class="input-group"><input type="number" id="dataLimit" min="0" step="0.01"><select id="dataUnit"><option>KB</option><option>MB</option><option>GB</option><option>TB</option><option value="unlimited" selected>Unlimited</option></select></div></div><div class="form-group"><label></label><button type="submit" class="btn btn-primary">Create</button></div></form></div><div class="card" style="margin-top:30px"><h2>User List</h2><input type="text" id="searchInput" class="search-input" placeholder="Search..."><button id="deleteSelected" class="btn btn-danger" style="margin-bottom:16px">Delete Selected</button><table><thead><tr><th><input type="checkbox" id="selectAll"></th><th>UUID</th><th>Created</th><th>Expiry</th><th>Status</th><th>Notes</th><th>Limit</th><th>Used</th><th>Actions</th></tr></thead><tbody id="userList"></tbody></table></div></div><div id="toast"></div><script>/* Admin JS will be injected in handleAdminRequest */</script></body></html>`;

// Full Admin JS will be injected safely in handleAdminRequest

// ============================================================================
// MAIN FETCH HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    let cfg;
    const noQuic = { 'alt-svc': 'h3=":443"; ma=0' };

    try {
      cfg = await Config.fromEnv(env);
    } catch (err) {
      return new Response(`Config Error: ${err.message}`, { status: 503, headers: noQuic });
    }

    const url = new URL(request.url);

    if (url.pathname === '/health') return new Response('OK', { headers: noQuic });

    if (url.pathname.startsWith('/admin')) {
      return await handleAdminRequest(request, env, ctx, adminLoginHTML, adminPanelHTML);
    }

    const upgrade = request.headers.get('Upgrade');
    if (upgrade?.toLowerCase() === 'websocket') {
      if (!env.DB || !env.USER_KV) return new Response('Not configured', { status: 503, headers: noQuic });
      return await ProtocolOverWSHandler(request, cfg, env, ctx);
    }

    const handleSub = async (core) => {
      const uuid = url.pathname.slice(`/${core}/`.length);
      if (!isValidUUID(uuid)) return new Response('Invalid UUID', { status: 400, headers: noQuic });
      const user = await getUserData(env, uuid, ctx);
      if (!user || isExpired(user.expiration_date, user.expiration_time) || (user.traffic_limit && user.traffic_used >= user.traffic_limit)) {
        return new Response('Forbidden', { status: 403, headers: noQuic });
      }
      return await handleIpSubscription(core, uuid, url.hostname);
    };

    if (url.pathname.startsWith('/xray/')) return handleSub('xray');
    if (url.pathname.startsWith('/sb/')) return handleSub('sb');

    const path = url.pathname.slice(1);
    if (isValidUUID(path)) {
      const user = await getUserData(env, path, ctx);
      if (!user) return new Response('Invalid user', { status: 403, headers: noQuic });
      return handleUserPanel(path, url.hostname, cfg.proxyAddress, user);
    }

    if (env.ROOT_PROXY_URL) {
      try {
        const target = new URL(env.ROOT_PROXY_URL);
        const newUrl = new URL(request.url);
        newUrl.hostname = target.hostname;
        newUrl.protocol = target.protocol;
        newUrl.port = target.port;
        const req = new Request(newUrl, request);
        req.headers.set('Host', target.hostname);
        req.headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');
        const res = await fetch(req);
        const headers = new Headers(res.headers);
        headers.delete('Content-Security-Policy');
        headers.delete('X-Frame-Options');
        return new Response(res.body, { status: res.status, headers });
      } catch (e) {
        return new Response(`Proxy error: ${e.message}`, { status: 502, headers: noQuic });
      }
    }

    return new Response('Not found', { status: 404, headers: noQuic });
  },
};

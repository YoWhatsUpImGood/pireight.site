// ============================================================
// Pireight.site — Cloudflare Worker Backend
// Paste this entire file into your Worker editor on Cloudflare
// ============================================================
//
// SETUP REQUIRED:
// 1. Create a D1 database named "proxy-users" in Cloudflare
// 2. Bind it to this Worker as DB in Worker Settings > Bindings
// 3. Run the SQL setup below in D1 Console:
//
//    CREATE TABLE IF NOT EXISTS users (
//      id INTEGER PRIMARY KEY AUTOINCREMENT,
//      email TEXT UNIQUE NOT NULL,
//      password_hash TEXT NOT NULL,
//      token TEXT UNIQUE,
//      verified INTEGER DEFAULT 0,
//      verify_code TEXT,
//      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
//    );
//
// 4. Set these environment variables in Worker Settings > Variables:
//    - RESEND_API_KEY  (get free key at resend.com)
//    - FROM_EMAIL      (e.g. noreply@pireight.site)
//    - JWT_SECRET      (any long random string)
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    try {
      // Routes
      if (path === '/api/signup' && request.method === 'POST') {
        return await handleSignup(request, env, headers);
      }
      if (path === '/api/verify' && request.method === 'GET') {
        return await handleVerify(request, env, headers);
      }
      if (path === '/api/login' && request.method === 'POST') {
        return await handleLogin(request, env, headers);
      }
      if (path === '/api/account' && request.method === 'GET') {
        return await handleAccount(request, env, headers);
      }

      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers });

    } catch (err) {
      console.error(err);
      return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500, headers });
    }
  }
};

// ─── SIGNUP ──────────────────────────────────────────────────
async function handleSignup(request, env, headers) {
  const { email, password } = await request.json();

  if (!email || !password) {
    return json({ error: 'Email and password required' }, 400, headers);
  }

  if (password.length < 8) {
    return json({ error: 'Password must be at least 8 characters' }, 400, headers);
  }

  if (!email.includes('@') || !email.includes('.')) {
    return json({ error: 'Invalid email address' }, 400, headers);
  }

  // Check if email already exists
  const existing = await env.DB.prepare(
    'SELECT id FROM users WHERE email = ?'
  ).bind(email.toLowerCase()).first();

  if (existing) {
    return json({ error: 'An account with this email already exists' }, 409, headers);
  }

  // Hash password
  const passwordHash = await hashPassword(password);

  // Generate verify code
  const verifyCode = generateToken(32);

  // Insert user
  await env.DB.prepare(
    'INSERT INTO users (email, password_hash, verify_code) VALUES (?, ?, ?)'
  ).bind(email.toLowerCase(), passwordHash, verifyCode).run();

  // Send verification email
  await sendVerificationEmail(email, verifyCode, env);

  return json({ message: 'Account created. Check your email to verify.' }, 201, headers);
}

// ─── VERIFY EMAIL ────────────────────────────────────────────
async function handleVerify(request, env, headers) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');

  if (!code) {
    return new Response('Missing verification code.', { status: 400 });
  }

  const user = await env.DB.prepare(
    'SELECT id FROM users WHERE verify_code = ? AND verified = 0'
  ).bind(code).first();

  if (!user) {
    return new Response('Invalid or already used verification link.', { status: 400 });
  }

  // Generate proxy token
  const token = generateToken(48);

  await env.DB.prepare(
    'UPDATE users SET verified = 1, token = ?, verify_code = NULL WHERE id = ?'
  ).bind(token, user.id).run();

  // Return a nice HTML confirmation page
  return new Response(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Pireight — Verified</title>
      <link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=DM+Mono:wght@400&display=swap" rel="stylesheet"/>
      <style>
        body { background: #0a0a0a; color: #f5f5f0; font-family: 'DM Mono', monospace; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .box { text-align: center; border: 1px solid #2e2e2e; padding: 4rem; max-width: 500px; }
        h1 { font-family: 'Bebas Neue'; font-size: 3rem; margin-bottom: 1rem; }
        p { color: #888; font-size: 0.85rem; line-height: 1.8; margin-bottom: 1rem; }
        .token { background: #1a1a1a; border: 1px solid #2e2e2e; padding: 1rem; word-break: break-all; font-size: 0.75rem; color: #f5f5f0; margin: 1.5rem 0; }
        a { color: #f5f5f0; text-decoration: underline; font-size: 0.8rem; }
      </style>
    </head>
    <body>
      <div class="box">
        <h1>Verified</h1>
        <p>Your email has been verified. Your proxy token is:</p>
        <div class="token">${token}</div>
        <p>Save this token — it's your key to access the proxy. Do not share it with anyone.</p>
        <a href="/">← Back to Pireight</a>
      </div>
    </body>
    </html>
  `, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// ─── LOGIN ───────────────────────────────────────────────────
async function handleLogin(request, env, headers) {
  const { email, password } = await request.json();

  if (!email || !password) {
    return json({ error: 'Email and password required' }, 400, headers);
  }

  const user = await env.DB.prepare(
    'SELECT id, password_hash, token, verified FROM users WHERE email = ?'
  ).bind(email.toLowerCase()).first();

  if (!user) {
    return json({ error: 'Invalid email or password' }, 401, headers);
  }

  const valid = await verifyPassword(password, user.password_hash);

  if (!valid) {
    return json({ error: 'Invalid email or password' }, 401, headers);
  }

  if (!user.verified) {
    return json({ error: 'Please verify your email before logging in.' }, 403, headers);
  }

  return json({ token: user.token }, 200, headers);
}

// ─── ACCOUNT INFO ────────────────────────────────────────────
async function handleAccount(request, env, headers) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) {
    return json({ error: 'Unauthorized' }, 401, headers);
  }

  const token = auth.slice(7);
  const user = await env.DB.prepare(
    'SELECT id, email, created_at FROM users WHERE token = ? AND verified = 1'
  ).bind(token).first();

  if (!user) {
    return json({ error: 'Invalid token' }, 401, headers);
  }

  return json({ email: user.email, created_at: user.created_at }, 200, headers);
}

// ─── HELPERS ─────────────────────────────────────────────────
function json(data, status, headers) {
  return new Response(JSON.stringify(data), { status, headers });
}

function generateToken(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => chars[b % chars.length]).join('');
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = generateToken(16);
  const data = encoder.encode(salt + password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hash));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return salt + ':' + hashHex;
}

async function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const encoder = new TextEncoder();
  const data = encoder.encode(salt + password);
  const computed = await crypto.subtle.digest('SHA-256', data);
  const computedArray = Array.from(new Uint8Array(computed));
  const computedHex = computedArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return computedHex === hash;
}

async function sendVerificationEmail(email, code, env) {
  const verifyUrl = `https://pireight.site/api/verify?code=${code}`;

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.FROM_EMAIL || 'noreply@pireight.site',
      to: email,
      subject: 'Verify your Pireight account',
      html: `
        <div style="background:#0a0a0a;color:#f5f5f0;font-family:monospace;padding:3rem;max-width:500px;margin:0 auto;">
          <h1 style="font-size:2rem;margin-bottom:1rem;letter-spacing:0.1em;">PIREIGHT</h1>
          <p style="color:#888;line-height:1.8;margin-bottom:2rem;">
            Click the link below to verify your email address and receive your proxy token.
            This link expires in 24 hours.
          </p>
          <a href="${verifyUrl}" style="display:inline-block;background:#f5f5f0;color:#0a0a0a;padding:1rem 2rem;text-decoration:none;font-weight:bold;letter-spacing:0.1em;">
            VERIFY EMAIL
          </a>
          <p style="color:#555;font-size:0.75rem;margin-top:2rem;line-height:1.6;">
            If you did not create this account, ignore this email.<br/>
            pireight.site
          </p>
        </div>
      `
    })
  });
}

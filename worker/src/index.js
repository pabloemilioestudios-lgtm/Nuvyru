// Nuvyru API · Fase 2: cuentas y publicaciones (Cloudflare Workers + D1)
const enc = new TextEncoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rand = (n = 32) => b64(crypto.getRandomValues(new Uint8Array(n)));
const sha = async (s) => b64(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const pbkdf2 = async (pw, salt) =>
  b64(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 100000 },
    await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]), 256));
const same = (a, b) => a.length === b.length && [...a].reduce((x, c, i) => x | (c.charCodeAt(0) ^ b.charCodeAt(i)), 0) === 0;

const cors = (req, env) => {
  const list = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
  const o = req.headers.get("Origin");
  return {
    "Access-Control-Allow-Origin": list.includes(o) ? o : list[0] || "null",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    Vary: "Origin",
  };
};
const json = (req, env, body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...cors(req, env) } });

async function readBody(req) {
  if (Number(req.headers.get("Content-Length") || 0) > 10000) return null;
  try { return await req.json(); } catch { return null; }
}
async function limit(env, key, max, sec) {
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare("SELECT count, start FROM nv_rate WHERE k=?").bind(key).first();
  if (!row || now - row.start >= sec) {
    await env.DB.prepare("INSERT OR REPLACE INTO nv_rate (k,count,start) VALUES (?,?,?)").bind(key, 1, now).run();
    return true;
  }
  if (row.count >= max) return false;
  await env.DB.prepare("UPDATE nv_rate SET count=count+1 WHERE k=?").bind(key).run();
  return true;
}
async function auth(req, env) {
  const h = req.headers.get("Authorization") || "";
  if (!h.startsWith("Bearer ")) return null;
  return env.DB.prepare(
    "SELECT u.id,u.username,u.display_name,u.bio FROM nv_sessions s JOIN nv_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?"
  ).bind(await sha(h.slice(7)), Date.now()).first();
}
async function newSession(env, uid) {
  const t = rand();
  await env.DB.prepare("INSERT INTO nv_sessions (token_hash,user_id,expires_at) VALUES (?,?,?)").bind(await sha(t), uid, Date.now() + 30 * 864e5).run();
  await env.DB.prepare("DELETE FROM nv_sessions WHERE expires_at<?").bind(Date.now()).run();
  return t;
}
const pub = (u) => ({ username: u.username, display_name: u.display_name, bio: u.bio });

const POSTS_SQL = `SELECT p.id,p.body,p.visibility,p.created_at,u.username,u.display_name,
 (SELECT COUNT(*) FROM nv_likes l WHERE l.post_id=p.id) AS like_count,
 EXISTS(SELECT 1 FROM nv_likes l WHERE l.post_id=p.id AND l.user_id=?1) AS liked,
 EXISTS(SELECT 1 FROM nv_saves s WHERE s.post_id=p.id AND s.user_id=?1) AS saved
 FROM nv_posts p JOIN nv_users u ON u.id=p.user_id
 WHERE (p.visibility='public' OR p.user_id=?1) AND (?2 IS NULL OR u.username=?2) AND (?3 IS NULL OR p.created_at<?3)
 ORDER BY p.created_at DESC LIMIT 30`;

const PLANNED = { "/api/comments": 3, "/api/follows": 3, "/api/notifications": 3, "/api/search": 3, "/api/media": 4, "/api/messages": 4, "/api/badges": 5, "/api/orya": 6, "/api/live": 7 };

// ---- Mascotas (Fase 5). El tiempo y todas las reglas viven en el servidor.
const HATCH_MS = 4 * 3600e3, FLOOR = 30, DAILY_XP = 60, DECAY_PER_H = 1;
const SPECIES = ["nubi", "lumo", "brisa", "zafi"], DEF = { nubi: "Nubi", lumo: "Lumo", brisa: "Brisa", zafi: "Zafi" };
const CARE = {
  feed: { cd: 1800, energy: 20, joy: 5, xp: 5, col: "last_feed" },
  play: { cd: 1200, energy: -8, joy: 15, xp: 8, col: "last_play", minEnergy: 10 },
  rest: { cd: 3600, energy: 30, joy: 0, xp: 2, col: "last_rest" },
  cuddle: { cd: 600, energy: 0, joy: 8, xp: 2, col: "last_cuddle" },
};
const STAGES = ["cria", "joven", "adulto"], UNLOCK = { hat: "cria", glasses: "joven", scarf: "adulto" };
const stageOf = (xp) => (xp >= 300 ? "adulto" : xp >= 100 ? "joven" : "cria");
const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)));
const day = (t) => new Date(t).toISOString().slice(0, 10);
// La energía y la alegría bajan despacio pero NUNCA por debajo de FLOOR: descansar no castiga.
const decay = (v, hrs) => (v <= FLOOR ? v : Math.max(FLOOR, v - hrs * DECAY_PER_H));
function petView(r, now) {
  if (r.status === "egg") return { status: "egg", hatch_at: r.hatch_at, hatch_in_ms: Math.max(0, r.hatch_at - now) };
  const hrs = r.rest_mode ? 0 : Math.max(0, (now - r.updated_at) / 36e5), st = stageOf(r.xp), cooldowns = {};
  for (const [k, c] of Object.entries(CARE)) cooldowns[k] = Math.max(0, Math.ceil((r[c.col] + c.cd * 1000 - now) / 1000));
  return {
    status: "hatched", species: r.species, name: r.name, stage: st, xp: r.xp, next_xp: st === "cria" ? 100 : st === "joven" ? 300 : null,
    energy: Math.round(decay(r.energy, hrs)), joy: Math.round(decay(r.joy, hrs)), accessory: r.accessory,
    show_on_profile: !!r.show_on_profile, reminders: !!r.reminders, rest_mode: !!r.rest_mode,
    cooldowns, xp_today: r.xp_day === day(now) ? r.xp_today : 0, daily_xp_cap: DAILY_XP,
  };
}
async function getPet(env, uid, now) {
  const q = () => env.DB.prepare("SELECT * FROM nv_pets WHERE user_id=?").bind(uid).first();
  let r = await q();
  if (r && r.status === "egg" && now >= r.hatch_at) {
    const sp = SPECIES[crypto.getRandomValues(new Uint32Array(1))[0] % SPECIES.length];
    await env.DB.prepare("UPDATE nv_pets SET status='hatched',species=?,name=?,hatched_at=?,energy=70,joy=70,updated_at=? WHERE user_id=?").bind(sp, DEF[sp], now, now, uid).run();
    r = await q();
  }
  return r;
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(req, env) });
    const url = new URL(req.url), p = url.pathname, m = req.method;
    const out = (b, s = 200) => json(req, env, b, s);
    const fail = (s, error, message) => out({ error, message }, s);
    try {
      if (p === "/api/health") return out({ ok: true, service: "nuvyru-api", db: !!env.DB });
      const hit = Object.keys(PLANNED).find((k) => p.startsWith(k));
      if (hit) return fail(501, "not_implemented", "Esta función llega en la fase " + PLANNED[hit]);
      if (!env.DB) return fail(503, "no_db", "La base de datos D1 no está configurada");
      const ip = req.headers.get("CF-Connecting-IP") || "local";

      if (p === "/api/auth/register" && m === "POST") {
        if (!(await limit(env, "reg:" + ip, 5, 3600))) return fail(429, "rate_limited", "Demasiados intentos. Inténtalo más tarde");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const username = String(b.username || "").trim().toLowerCase(), name = String(b.display_name || "").trim();
        const pw = String(b.password || ""), by = Number(b.birth_year), yr = new Date().getFullYear();
        if (!/^[a-z0-9_.]{3,24}$/.test(username)) return fail(400, "invalid_username", "El usuario debe tener de 3 a 24 caracteres: letras, números, punto o guion bajo");
        if (name.length < 1 || name.length > 40) return fail(400, "invalid_name", "Escribe tu nombre (máximo 40 caracteres)");
        if (pw.length < 8 || pw.length > 128) return fail(400, "invalid_password", "La contraseña debe tener entre 8 y 128 caracteres");
        if (!Number.isInteger(by) || by < 1900 || by > yr) return fail(400, "invalid_birth", "Escribe un año de nacimiento válido");
        if (yr - by < 13) return fail(403, "underage", "Debes tener al menos 13 años para crear una cuenta");
        if (await env.DB.prepare("SELECT 1 FROM nv_users WHERE username=?").bind(username).first()) return fail(409, "username_taken", "Ese nombre de usuario ya existe");
        const id = crypto.randomUUID(), salt = rand(16), hash = await pbkdf2(pw, salt);
        try {
          await env.DB.prepare("INSERT INTO nv_users (id,username,display_name,bio,pass_hash,pass_salt,birth_year,created_at) VALUES (?,?,?,?,?,?,?,?)")
            .bind(id, username, name, "", hash, salt, by, Date.now()).run();
        } catch { return fail(409, "username_taken", "Ese nombre de usuario ya existe"); }
        return out({ token: await newSession(env, id), user: { username, display_name: name, bio: "" } }, 201);
      }
      if (p === "/api/auth/login" && m === "POST") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const username = String(b.username || "").trim().toLowerCase(), pw = String(b.password || "").slice(0, 128);
        if (!(await limit(env, "login:" + ip + ":" + username, 10, 900))) return fail(429, "rate_limited", "Demasiados intentos. Espera unos minutos");
        const row = await env.DB.prepare("SELECT id,username,display_name,bio,pass_hash,pass_salt FROM nv_users WHERE username=?").bind(username).first();
        const h = await pbkdf2(pw, row ? row.pass_salt : "x".repeat(22));
        if (!row || !same(h, row.pass_hash)) return fail(401, "invalid_credentials", "Usuario o contraseña incorrectos");
        return out({ token: await newSession(env, row.id), user: pub(row) });
      }

      const me = await auth(req, env);
      if (!me) return fail(401, "unauthorized", "Inicia sesión para continuar");

      if (p === "/api/auth/logout" && m === "POST") {
        await env.DB.prepare("DELETE FROM nv_sessions WHERE token_hash=?").bind(await sha(req.headers.get("Authorization").slice(7))).run();
        return out({ ok: true });
      }
      if (p === "/api/me" && m === "GET") return out({ user: pub(me) });
      if (p === "/api/me" && m === "PATCH") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const name = b.display_name === undefined ? me.display_name : String(b.display_name).trim();
        const bio = b.bio === undefined ? me.bio : String(b.bio).trim();
        if (name.length < 1 || name.length > 40) return fail(400, "invalid_name", "El nombre debe tener entre 1 y 40 caracteres");
        if (bio.length > 160) return fail(400, "invalid_bio", "La biografía admite hasta 160 caracteres");
        await env.DB.prepare("UPDATE nv_users SET display_name=?, bio=? WHERE id=?").bind(name, bio, me.id).run();
        return out({ user: { username: me.username, display_name: name, bio } });
      }
      if (p === "/api/me" && m === "DELETE") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const row = await env.DB.prepare("SELECT pass_hash,pass_salt FROM nv_users WHERE id=?").bind(me.id).first();
        if (!same(await pbkdf2(String(b.password || "").slice(0, 128), row.pass_salt), row.pass_hash)) return fail(403, "invalid_credentials", "Contraseña incorrecta");
        await env.DB.batch([
          env.DB.prepare("DELETE FROM nv_likes WHERE post_id IN (SELECT id FROM nv_posts WHERE user_id=?) OR user_id=?").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_saves WHERE post_id IN (SELECT id FROM nv_posts WHERE user_id=?) OR user_id=?").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_posts WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_pets WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_sessions WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_users WHERE id=?").bind(me.id),
        ]);
        return out({ ok: true });
      }

      if (p === "/api/posts" && m === "GET") {
        const u = (url.searchParams.get("user") || "").toLowerCase() || null, before = Number(url.searchParams.get("before")) || null;
        const { results } = await env.DB.prepare(POSTS_SQL).bind(me.id, u, before).all();
        return out({ posts: results.map((r) => ({ ...r, liked: !!r.liked, saved: !!r.saved, mine: r.username === me.username })) });
      }
      if (p === "/api/posts" && m === "POST") {
        if (!(await limit(env, "post:" + me.id, 20, 3600))) return fail(429, "rate_limited", "Has publicado demasiado. Inténtalo en un rato");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const text = String(b.body || "").trim(), vis = b.visibility === "private" ? "private" : "public";
        if (!text || text.length > 500) return fail(400, "invalid_body", "La publicación debe tener entre 1 y 500 caracteres");
        const id = crypto.randomUUID(), now = Date.now();
        await env.DB.prepare("INSERT INTO nv_posts (id,user_id,body,visibility,created_at) VALUES (?,?,?,?,?)").bind(id, me.id, text, vis, now).run();
        return out({ post: { id, body: text, visibility: vis, created_at: now, username: me.username, display_name: me.display_name, like_count: 0, liked: false, saved: false, mine: true } }, 201);
      }
      if (p === "/api/pet" && m === "GET") {
        const now = Date.now(), r = await getPet(env, me.id, now);
        return out({ pet: r ? petView(r, now) : null });
      }
      if (p === "/api/pet/request" && m === "POST") {
        if (!(await limit(env, "petreq:" + me.id, 3, 86400))) return fail(429, "rate_limited", "Has pedido demasiadas mascotas hoy");
        if (await env.DB.prepare("SELECT 1 FROM nv_pets WHERE user_id=?").bind(me.id).first()) return fail(409, "already_has_pet", "Ya tienes una mascota o un huevo");
        const now = Date.now();
        await env.DB.prepare("INSERT INTO nv_pets (user_id,status,requested_at,hatch_at,updated_at) VALUES (?,'egg',?,?,?)").bind(me.id, now, now + HATCH_MS, now).run();
        return out({ pet: petView(await getPet(env, me.id, now), now) }, 201);
      }
      if (p === "/api/pet/care" && m === "POST") {
        const b = await readBody(req), c = b && Object.hasOwn(CARE, b.action) ? CARE[b.action] : null;
        if (!c) return fail(400, "invalid_action", "Acción no válida");
        if (!(await limit(env, "care:" + me.id, 60, 3600))) return fail(429, "rate_limited", "Demasiadas acciones seguidas");
        const now = Date.now(), r = await getPet(env, me.id, now);
        if (!r || r.status !== "hatched") return fail(409, "not_hatched", "Tu mascota aún no ha eclosionado");
        if (r.rest_mode) return fail(409, "rest_mode", "El modo descanso está activado");
        const left = Math.ceil((r[c.col] + c.cd * 1000 - now) / 1000);
        if (left > 0) return out({ error: "cooldown", message: "Todavía no es momento. Vuelve en " + Math.ceil(left / 60) + " min", retry_in: left }, 429);
        const hrs = Math.max(0, (now - r.updated_at) / 36e5);
        let e = decay(r.energy, hrs), j = decay(r.joy, hrs);
        if (c.minEnergy && e < c.minEnergy) return fail(409, "tired", "Está muy cansado para jugar. Déjalo descansar");
        e = clamp(e + c.energy); j = clamp(j + c.joy);
        const used = r.xp_day === day(now) ? r.xp_today : 0, gain = Math.max(0, Math.min(c.xp, DAILY_XP - used));
        await env.DB.prepare(`UPDATE nv_pets SET energy=?,joy=?,xp=xp+?,xp_day=?,xp_today=?,updated_at=?,${c.col}=? WHERE user_id=?`).bind(e, j, gain, day(now), used + gain, now, now, me.id).run();
        return out({ pet: petView(await getPet(env, me.id, now), now), gained: gain });
      }
      if (p === "/api/pet" && m === "PATCH") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const now = Date.now(), r = await getPet(env, me.id, now);
        if (!r || r.status !== "hatched") return fail(409, "not_hatched", "Tu mascota aún no ha eclosionado");
        let name = r.name, acc = r.accessory;
        if (b.name !== undefined) {
          name = String(b.name).trim();
          if (!/^[\p{L}\p{N} ._'-]{1,20}$/u.test(name)) return fail(400, "invalid_name", "El nombre debe tener de 1 a 20 caracteres (letras, números o espacios)");
        }
        if (b.accessory !== undefined) {
          acc = String(b.accessory);
          if (acc !== "none" && !Object.hasOwn(UNLOCK, acc)) return fail(400, "invalid_accessory", "Accesorio no válido");
          if (acc !== "none" && STAGES.indexOf(stageOf(r.xp)) < STAGES.indexOf(UNLOCK[acc])) return fail(403, "locked", "Ese accesorio se desbloquea al evolucionar");
        }
        const flag = (k) => (b[k] === undefined ? r[k] : b[k] ? 1 : 0);
        const hrs = r.rest_mode ? 0 : Math.max(0, (now - r.updated_at) / 36e5);
        await env.DB.prepare("UPDATE nv_pets SET name=?,accessory=?,show_on_profile=?,reminders=?,rest_mode=?,energy=?,joy=?,updated_at=? WHERE user_id=?")
          .bind(name, acc, flag("show_on_profile"), flag("reminders"), flag("rest_mode"), Math.round(decay(r.energy, hrs)), Math.round(decay(r.joy, hrs)), now, me.id).run();
        return out({ pet: petView(await getPet(env, me.id, now), now) });
      }
      if (p === "/api/pet" && m === "DELETE") {
        await env.DB.prepare("DELETE FROM nv_pets WHERE user_id=?").bind(me.id).run();
        return out({ ok: true });
      }
      let mt;
      if ((mt = p.match(/^\/api\/posts\/([0-9a-f-]{36})\/(like|save)$/)) && m === "POST") {
        if (!(await limit(env, "act:" + me.id, 120, 60))) return fail(429, "rate_limited", "Demasiadas acciones seguidas");
        const ok = await env.DB.prepare("SELECT id FROM nv_posts WHERE id=? AND (visibility='public' OR user_id=?)").bind(mt[1], me.id).first();
        if (!ok) return fail(404, "not_found", "La publicación no existe");
        const t = mt[2] === "like" ? "nv_likes" : "nv_saves";
        const had = await env.DB.prepare(`SELECT 1 FROM ${t} WHERE post_id=? AND user_id=?`).bind(mt[1], me.id).first();
        await env.DB.prepare(had ? `DELETE FROM ${t} WHERE post_id=? AND user_id=?` : `INSERT INTO ${t} (post_id,user_id) VALUES (?,?)`).bind(mt[1], me.id).run();
        if (mt[2] === "save") return out({ saved: !had });
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM nv_likes WHERE post_id=?").bind(mt[1]).first();
        return out({ liked: !had, like_count: c.n });
      }
      if ((mt = p.match(/^\/api\/posts\/([0-9a-f-]{36})$/)) && m === "DELETE") {
        const r = await env.DB.prepare("DELETE FROM nv_posts WHERE id=? AND user_id=?").bind(mt[1], me.id).run();
        if (!r.meta.changes) return fail(404, "not_found", "La publicación no existe o no es tuya");
        await env.DB.batch([env.DB.prepare("DELETE FROM nv_likes WHERE post_id=?").bind(mt[1]), env.DB.prepare("DELETE FROM nv_saves WHERE post_id=?").bind(mt[1])]);
        return out({ ok: true });
      }
      return fail(404, "not_found", "Ruta no encontrada");
    } catch (e) {
      console.error(e);
      return fail(500, "server_error", "Error del servidor");
    }
  },
};

// Nuvyru API (esqueleto). Cada ruta responde 501 hasta su fase.
const ORIGINS = ["https://TU-USUARIO.github.io"]; // ajusta al dominio real de Pages

const cors = (req) => {
  const o = req.headers.get("Origin");
  return {
    "Access-Control-Allow-Origin": ORIGINS.includes(o) ? o : ORIGINS[0],
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    Vary: "Origin",
  };
};
const json = (req, body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...cors(req) } });

const PLANNED = {
  "/api/auth": 2, "/api/posts": 2, "/api/comments": 3, "/api/follows": 3,
  "/api/notifications": 3, "/api/search": 3, "/api/media": 4, "/api/messages": 4,
  "/api/pets": 5, "/api/badges": 5, "/api/orya": 6, "/api/live": 7,
};

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(req) });
    const { pathname } = new URL(req.url);
    if (pathname === "/api/health") return json(req, { ok: true, service: "nuvyru-api" });
    const hit = Object.keys(PLANNED).find((p) => pathname.startsWith(p));
    if (hit) return json(req, { error: "not_implemented", phase: PLANNED[hit] }, 501);
    return json(req, { error: "not_found" }, 404);
  },
};

# Nuvyru — Fase 1 (prototipo visual)

Estructura:
- `index.html` + `assets/`: frontend estático (GitHub Pages). Sin dependencias ni build.
- `worker/`: esqueleto de Cloudflare Worker (`/api/health` funciona; el resto devuelve 501 hasta su fase).

Probar el frontend: `npx serve .` (o `python3 -m http.server`) y abrir http://localhost:3000.
Probar el Worker: `cd worker && npx wrangler dev` y abrir /api/health.

Antes de copiar a tu repo: compara con lo que ya existe (sobre todo `index.html`, `wrangler.toml` y el Worker de Orya AI) y fusiona a mano, no sobrescribas.

# Nuvyru · Fase 2 (cuentas y publicaciones reales)

- `index.html`, `assets/`: frontend estático (GitHub Pages).
- `assets/config.js`: URL de tu Worker.
- `worker/`: API en Cloudflare Workers + D1 (`schema.sql`, `wrangler.toml`, `src/index.js`).

## Puesta en marcha
1. `cd worker && npx wrangler login`
2. `npx wrangler d1 list` → copia el nombre y el id de tu D1 en `wrangler.toml`.
3. En `wrangler.toml`, pon tu dominio real en `ALLOWED_ORIGIN` (ej. `https://usuario.github.io`, sin ruta).
4. `npx wrangler d1 execute NOMBRE_DB --remote --file=./schema.sql` (crea solo tablas `nv_*`).
5. `npx wrangler deploy` → copia la URL `https://nuvyru-api.XXXX.workers.dev`.
6. Pega esa URL en `assets/config.js` y sube todo a GitHub.
7. Comprueba `https://nuvyru-api.XXXX.workers.dev/api/health` → `{"ok":true,...,"db":true}`.

Las demás rutas (/api/search, /api/media…) responden 501 hasta su fase.

## Adaptación automática a dispositivos
La interfaz detecta el dispositivo al cargar y al girar o redimensionar la pantalla (`<html data-device="phone|tablet|desktop|tv">`):
- **Móvil:** una columna, barra flotante, áreas seguras (notch).
- **Tablet:** publicaciones en 2 columnas, texto algo mayor.
- **Computadora:** columna central, efectos al pasar el ratón, J/K o flechas para cambiar de video.
- **TV:** texto grande, 3 columnas, márgenes seguros, foco visible y manejo con el control remoto (flechas, OK y Atrás).
Se puede forzar en Ajustes → Pantalla, o con `?device=tv` en la dirección (para probar).

## Mascotas (Fase 5, primera parte)
Se piden por chat (solicitud → huevo → 4 h → eclosiona). Detalle de reglas y guía de montaje del backend en `BACKEND.md`.
**Si ya habías ejecutado `schema.sql`, vuelve a ejecutarlo** para crear la tabla `nv_pets`, y luego `npx wrangler deploy`.

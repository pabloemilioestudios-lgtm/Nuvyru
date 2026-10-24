# Cómo funciona el backend de Nuvyru (y cómo montarlo)

## 1. Las piezas
| Pieza | Qué es | Dónde vive |
|---|---|---|
| **Frontend** | Lo que ve la gente (`index.html`). Solo dibuja pantallas y pide datos. | GitHub Pages |
| **Worker** | Un programa pequeño en la nube (`worker/src/index.js`). Recibe peticiones, comprueba quién eres, aplica las reglas y habla con la base de datos. | Cloudflare Workers |
| **D1** | La base de datos (tablas `nv_*`): usuarios, publicaciones, mascotas… | Cloudflare D1 |

Regla de oro: **el frontend nunca decide nada importante**. Si el navegador dijera "mi huevo ya eclosionó", el Worker lo ignoraría: la hora y las reglas son del servidor.

## 2. Qué pasa cuando pulsas «Alimentar»
1. El navegador envía `POST /api/pet/care {"action":"feed"}` con tu token de sesión.
2. El Worker busca tu sesión en D1 (si no existe → 401).
3. Carga tu mascota, comprueba que ya eclosionó, que no esté en modo descanso y que pasaron 30 min desde la última comida (si no → 429 con el tiempo que falta).
4. Calcula energía, alegría y XP (con el tope de 60 XP al día) y lo guarda en D1.
5. Devuelve el estado nuevo y el navegador lo dibuja.

## 3. Montarlo paso a paso
Necesitas Node.js y una cuenta de Cloudflare. Todo se hace dentro de la carpeta `worker/`.
1. `npx wrangler login` → se abre el navegador, autoriza.
2. `npx wrangler d1 list` → copia el **nombre** y el **id** de tu D1.
3. Abre `wrangler.toml` y reemplaza `PENDIENTE` (nombre e id). Cambia `ALLOWED_ORIGIN` por tu dominio de GitHub Pages (ej. `https://usuario.github.io`, sin barra final ni nombre del repositorio).
4. Crea las tablas: `npx wrangler d1 execute NOMBRE_DB --remote --file=./schema.sql`
   (usa `IF NOT EXISTS`: puedes repetirlo sin borrar nada. **Repítelo ahora** para añadir la tabla `nv_pets`).
5. `npx wrangler deploy` → te da una URL `https://nuvyru-api.XXXX.workers.dev`.
6. Pega esa URL en `assets/config.js` y sube todo a GitHub.
7. Comprueba: abre `TU_URL/api/health` → debe verse `{"ok":true,"service":"nuvyru-api","db":true}`.

## 4. Probar sin el frontend
```
curl TU_URL/api/health
curl -X POST TU_URL/api/auth/register -H "Content-Type: application/json" \
  -d '{"username":"prueba","display_name":"Prueba","password":"contraseña123","birth_year":2000}'
# copia el "token" de la respuesta:
curl TU_URL/api/pet -H "Authorization: Bearer TOKEN"
curl -X POST TU_URL/api/pet/request -H "Authorization: Bearer TOKEN"
```

## 5. Ver y arreglar datos
- Ver mascotas: `npx wrangler d1 execute NOMBRE_DB --remote --command "SELECT user_id,status,species,name,xp,hatch_at FROM nv_pets"`
- Ver el log en vivo: `npx wrangler tail`
- Para probar la eclosión sin esperar 4 h (solo en tu pruebas): `UPDATE nv_pets SET hatch_at=0 WHERE user_id='ID'`

## 6. Cada vez que cambies el código
`cd worker && npx wrangler deploy`. Si cambió `schema.sql`, ejecútalo otra vez (paso 4).

## 7. Errores típicos
| Síntoma | Causa | Solución |
|---|---|---|
| El navegador dice "No se pudo conectar con el servidor" | CORS o URL mal | `ALLOWED_ORIGIN` debe ser exactamente el dominio de la web; revisa `assets/config.js` |
| `503 no_db` | D1 no enlazada | Revisa `database_id` en `wrangler.toml` y vuelve a hacer deploy |
| `401` al abrir la app | Token caducado (30 días) | Inicia sesión otra vez |
| `no such table: nv_pets` | Falta ejecutar `schema.sql` | Paso 4 |
| `429 rate_limited` | Límite anti-abuso | Espera unos minutos |

## 8. Seguridad
- Las contraseñas se guardan con PBKDF2 + sal; nunca en texto plano.
- Claves futuras (Orya AI, video LIVE): `npx wrangler secret put NOMBRE`. **Nunca** en archivos de GitHub.
- No subas `.dev.vars` ni archivos con claves.

## 9. Reglas de las mascotas (todas en el servidor)
- Solicitud → huevo; **eclosiona a las 4 h** (`hatch_at` guardado al pedirlo). Especie al azar entre 4.
- Cuidado: alimentar (30 min de espera), jugar (20), descansar (60), mimar (10).
- Máximo **60 XP al día**: sin presión de entrar a diario. Etapas: Cría → Joven (100 XP) → Adulto (300 XP).
- Energía y alegría bajan despacio pero **nunca de 30**; no hay pérdida de progreso ni la mascota se escapa.
- **Modo descanso:** pausa el cuidado y el desgaste.
- Accesorios: Gorro (cría), Gafas (joven), Bufanda (adulto).

## 10. Fotos y videos (R2)
1. Activa R2 en tu cuenta: dash.cloudflare.com → **R2 Object Storage** → activar (puede pedir una tarjeta; el plan gratuito incluye 10 GB y no cobra por la descarga).
2. Crea el almacenamiento: `npx wrangler r2 bucket create nuvyru-media`
3. `wrangler.toml` ya trae el bloque `[[r2_buckets]]`.
4. Vuelve a ejecutar `schema.sql` (añade las tablas de medios y perfiles) y haz `npx wrangler deploy`.
5. `/api/health` debe mostrar `"storage":true`.

Límites: fotos 8 MB (la app las reduce antes de subirlas), videos 100 MB. Se comprueba el contenido real del archivo, no solo su extensión.
Los archivos se sirven por una dirección con un identificador imposible de adivinar; quien no tenga ese enlace no puede verlos.

## 11. Denuncias, bloqueos y ajustes
**Bloqueos:** quien bloquea y la persona bloqueada dejan de verse en inicio, búsqueda, explorar, videos y perfiles. No se avisa a nadie.
**Denuncias:** se guardan en la tabla `nv_reports`. La otra persona nunca recibe aviso. Las de seguridad (peligro para menores, autolesión, violencia) quedan con `priority = 1`. Todavía no hay panel de moderación: las revisa quien administra, con estos comandos (en la carpeta `worker`):

Ver las denuncias abiertas, las prioritarias primero:
```
npx wrangler d1 execute orya-db --remote --command "SELECT r.id, r.priority, r.target_type, r.reason, r.details, datetime(r.created_at/1000,'unixepoch') AS fecha, r.target_id FROM nv_reports r WHERE r.status='open' ORDER BY r.priority DESC, r.created_at LIMIT 20"
```
Ver la publicación denunciada:
```
npx wrangler d1 execute orya-db --remote --command "SELECT p.id, u.username, p.body FROM nv_posts p JOIN nv_users u ON u.id=p.user_id WHERE p.id='ID_DE_LA_PUBLICACION'"
```
Quitar una publicación (y sus likes y guardados):
```
npx wrangler d1 execute orya-db --remote --command "DELETE FROM nv_likes WHERE post_id='ID'; DELETE FROM nv_saves WHERE post_id='ID'; DELETE FROM nv_post_media WHERE post_id='ID'; DELETE FROM nv_posts WHERE id='ID'"
```
Marcar una denuncia como resuelta:
```
npx wrangler d1 execute orya-db --remote --command "UPDATE nv_reports SET status='resuelta' WHERE id='ID_DE_LA_DENUNCIA'"
```
Si una denuncia habla de un menor en peligro inmediato, contacta a las autoridades de tu país; no esperes a revisarla aquí.

**Importante antes de abrir la app al público:** hace falta una persona que revise las denuncias con regularidad y un panel para hacerlo sin comandos (lo siguiente a construir).

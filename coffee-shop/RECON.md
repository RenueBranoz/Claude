# The Coffee Shop (hiCTF / HI Cyber Con 2026) — recon notes

Target: per-session instancer, host `the-coffee-shop-<hash>.chall.hiddeninvestigations.net`
(instance **expires** after a while → falls back to "HI Cyber Con 2026 / no instance deployed").
Goal: find the authorization token inside the head roaster's "private after-hours ledger".
Flag is almost certainly a file on the box (prior hiCTF `titan-relay` read `/flag.txt`).

## Stack
- Apache/2.4.69 (Debian), PHP/8.4.26, `X-Content-Type-Options: nosniff`. No cookies/sessions anywhere.
- Static landing page + client `/assets/site.js`. All dynamic calls go through `GET|POST /?api=<route>`.

## API surface (whitelist router; unknown route => `{"error":"Not found."}`)
- `GET /?api=menu` — fixed 9-product list, `updated:"2026-10-01"`. Ignores extra params.
- `POST /?api=order` (JSON) — create order.
  - Validates: name len 2–70, valid email, phone len 6–30; `items` each `{id,quantity}`;
    id must be a menu id; quantity integer 1–10 (string/array/neg/0/huge/float rejected).
  - `promo:"FIRSTSIP"` = 10% off. Returns `order.id = EO-<8 hex>`, `trackingToken = <48 hex>` (random_bytes, NOT predictable).
  - Storage is **server-global** (order created in one request is trackable from another with no cookie)
    => the roaster's order/ledger lives in the SAME store.
- `GET /?api=order&id=<>&token=<>` — track. Returns id,name,items,subtotal,discount,total,created,pickupAt,status.
- `POST /?api=newsletter` (JSON `{email}`) — just echoes a message.

## Tried & FAILED (all return generic errors, no signal)
- Token/id: SQLi (quotes, OR 1=1), type-juggling (`token[]`,`id[]`), loose compare (`token=0`), blank token,
  path traversal in `id` (`../etc/passwd`, `../ledger`, `x/../EO-...`), case, trailing space, `%00`.
  NOTE: the clean storage-detection run (traversal-equiv id + correct token) hit the dead instance — **RE-RUN on fresh instance**.
- Alt lookup keys: `email=`,`phone=`,`name=`,`all=`,`list=`,`id=*` — all "Order not found."
- LFI: `api=php://filter/...`, `api=../index`, `/etc/passwd`; top-level params page/file/include/view/tpl/etc. — none.
- Hidden menu: `menu&all/category/include/secret/debug/file/...` — ignored, full menu only.
- Files: robots/sitemap/index.php(200)/*.bak/~/.phps/.env/.git(403 blocked)/server-status(403)/backup zips — none readable.
  `.git` and dotfiles return 403 (Apache block); many `.git` encoding bypasses tried — all 403/404.
- Routes fuzzed: ledger, admin, login, auth, orders, roaster, books, vault, eod, nightly, register, cashbook, ... — only menu/order/newsletter exist.
- Order payload fuzz: no stack traces / info disclosure (errors are clean strings).
- Headers: X-Forwarded-For/Host, Authorization, X-Real-IP — no effect. `Host:` controls instancer vhost routing only.

## client site.js comments (likely hardening hints / red herrings)
- "Menu data authored server-side; user-controlled fields never interpolated" (menu XSS discouraged)
- "Tracking token is secret and only shown to the person who placed the order"
- "Treat persisted bag state as untrusted client data"

## SESSION 2 findings (instance 0ad7577c461b, later expires)
- Backend is **Apache/2.4.69 (Debian) on port 7107** behind the hiCTF instancer (Host-routed). REST-style codes (201/404/422/403/416).
- **Routes are exactly 4**: `menu` (GET), `order` (GET=track / POST=create), `newsletter` (POST), `health` (GET → `{"ok":true,"service":"ember-and-oak"}`). GET- and POST-brute of ~500 words each found nothing else. No param-gated route surfaced.
- **Auth binding is perfect**: cross-order id/token rejected; prefix/substring/empty/concat token rejected; case-sensitive exact id. No type-juggle, no SQLi (clean Python payloads in id/token/name/note/email — quotes stored & echoed verbatim ⇒ parameterized/file store).
- **Tokens**: harvested 64 orders. ids = random 32-bit (`EO-`+8 hex), tokens = 192-bit full-entropy (`random_bytes`). No id→token derivation (md5/sha1/sha256 of id/full tested), no ordering, no collisions ⇒ **not predictable**.
- **Mass-assignment**: server rebuilds order; injected id/token/status/total/discount/role ignored.
- **promo**: only `FIRSTSIP` valid (brute 936 themed codes). It's `strcasecmp(trim($promo),'FIRSTSIP')` → 10% off; `\u0000`/`\n`/`\t`/spaces trimmed; internal NUL & traversal & SSTI all invalid. Not an LFI/oracle beyond code validity.
- **pickup** whitelisted asap/30/45/60 (no date sink). **newsletter** POST-only, generic ok msg, no dedup oracle, email filter_var-validated, no SQLi.
- **note IS returned on track** (with valid id+token) — so reading an order = reading its note (the token would live there), but roaster order's id+token unknown & unguessable.
- **No SSTI** (name/note echoed verbatim), **no XXE** (XML rejected "Expected JSON request."), **no 500/stack traces**, **no reflection**, **no cookies/sessions ever set**.
- **File read**: `/flag.txt`,`/flag`,`/flag.php`,`/flag.html`,`/README.md`,`/.env`,`/.git/*`,`/.ht*`,`/server-status` → **403** (Apache deny; `.git/*` 403 even for nonexistent paths ⇒ Directory deny, git NOT dumpable). Random missing files/dotfiles → 404. Flag almost certainly at `/flag.txt`, blocked at Apache layer.
- **Apache bypasses tried & failed**: encoded dots/slashes (`%2e`,`%2f`,`..%2f`,`....//`,`%252e`), `--path-as-is` traversal, trailing `%00`/`;`/`%23`/space, case, `index.php/../`. Deny applies post-normalization to final segment.
- No per-order web artifacts (`/orders/<id>`, `/receipts/...`), no admin tooling (adminer/pma), no sourcemaps, no hidden assets, CSS/JS clean.

## CONCLUSION (session 2): standard black-box surface is exhausted & hardened.
Remaining plausible intended vulns (need source or heavier tooling):
1. **HTTP request smuggling / proxy desync** between the HTTP/2 instancer front and backend Apache 2.4.69 → reach an internal-only "ledger" endpoint ("not on the menu" = internal). Hard to drive reliably via curl here.
2. A subtle logic/crypto flaw only visible in **source** (hiCTF challenges often ship a handout zip — worth getting).
3. Time-gated "after-hours" behavior we can't trigger (server clock not controllable). It IS currently after-hours (server UTC, shop opens 8am) and nothing unlocked.

## SESSION 3 additions (all negative)
- Order endpoint param-mine (GET track + no-id) across ~80 param names: no hidden param changes behavior.
- null-token hypothesis: brute ~100 themed/numeric ledger ids with token omitted / `token=null` / `token[]=` → 0 hits.
- nginx alias off-by-slash + front/back path discrepancy (`/assets../`, `/assets..%2f`, `%2e%2e`, `..;/`, `..%00/`) → 404/403, no flag read.
- WebDAV: PROPFIND/PROPPATCH/REPORT/MKCOL/COPY/MOVE/LOCK/SEARCH on `/` all return the homepage (PHP ignores method); on `/assets/` → 405. TRACE → 405. No listing. OPTIONS → no Allow/DAV header.
- Direct backend ports (7107/8443/8080/80) unreachable (egress is 443-only; connection reset / no-resolve).
- Host header rewrite → instancer "no instance" page (front routes by Host). X-Forwarded-*/Forwarded → no effect.
- Menu: exactly 9 products, categories {coffee,tea,bakery,kitchen} only, no extra fields, no hidden category/product.
- Headers everywhere: `cache-control: no-store`, `x-content-type-options: nosniff`, `x-powered-by: PHP/8.4.26`, `server: Apache/2.4.69 (Debian) ... Port 7107`. No auth token / cookie / Link / X-* leak. Roaster email in order = neutral.
- health is static `{"ok":true,"service":"ember-and-oak"}` under all params/methods.

## STRONGEST REMAINING HYPOTHESIS
An internal/after-hours-gated endpoint (the "ledger") that the front-proxy hides or that the app restricts by source/header — reachable only by **HTTP request smuggling** (desync instancer↔Apache) to bypass the front proxy's header handling. Could NOT attempt from this sandbox: proxy credentials/raw-socket access are blocked by the environment classifier, and the backend isn't directly reachable. Needs either source (to confirm the gate + route) or a less-restricted testing box.

## Ideas to try next (fresh instance)
1. Re-run storage-detection: `id = x/../EO-<id>` with CORRECT token — if it returns the order, storage is naive
   per-id file concat => path traversal to read `../ledger.json` / `/flag.txt` (must yield valid order-ish JSON, or token gate bypass).
2. "after-hours" = time-based: probe same endpoints and look for behavior that depends on server clock / a state.
3. Second-order: does `note`/`name`/`promo` get stored and rendered in some roaster/ledger view? (needs that view)
4. Bigger route + param wordlist; check OPTIONS/TRACE; look for a second vhost/path for the ledger.
5. Re-examine token compare for `hash_equals` vs `==` nuances; try unicode/normalization on id.

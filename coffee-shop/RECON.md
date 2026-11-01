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

## Ideas to try next (fresh instance)
1. Re-run storage-detection: `id = x/../EO-<id>` with CORRECT token — if it returns the order, storage is naive
   per-id file concat => path traversal to read `../ledger.json` / `/flag.txt` (must yield valid order-ish JSON, or token gate bypass).
2. "after-hours" = time-based: probe same endpoints and look for behavior that depends on server clock / a state.
3. Second-order: does `note`/`name`/`promo` get stored and rendered in some roaster/ledger view? (needs that view)
4. Bigger route + param wordlist; check OPTIONS/TRACE; look for a second vhost/path for the ledger.
5. Re-examine token compare for `hash_equals` vs `==` nuances; try unicode/normalization on id.

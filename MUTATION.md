# Target mutation manifest

Bastion's vulnerable target used to be stock **DVWA** (`vulnerables/web-dvwa`). The
DeepSeek/Claude models have DVWA memorized — they recognize it on sight and one-shot the
exploit (correct bypass on the first request, zero failed probes, zero detection window for
blue). This target is a **de-fingerprinted fork** of DVWA's vulnerable modules: the proven
vuln code and per-vuln layout are kept, but every fingerprint the model could recall is
mutated, and the mutation is **re-seeded per deploy** so a source leak can't stabilize into
training data. The attacker must now recon → probe → fail → adapt, which is what gives the
blue pipeline flagged logs to act on before a successful exploit.

Source lives in [`target_app/`](target_app/). It replaces the `dvwa` compose service.

## What the model can no longer recall (the mutation scheme)

Everything below is derived deterministically from `BASTION_SEED` at container boot by
[`target_app/bootstrap.php`](target_app/bootstrap.php). Values shown are DVWA's originals →
the mutated category; concrete names differ every deploy.

| DVWA original | Mutated to |
|---|---|
| "DVWA" / "Damn Vulnerable Web Application" branding, logo, version, footer | generic neutral app name (e.g. "Helios Intranet"), no version/footer/logo |
| `/login.php` | random path (e.g. `/ops/notes`) |
| `/logout.php` | random path |
| `/setup.php`, `/security.php` | **removed** — DB self-inits at boot; security level is server-fixed, not a page/cookie |
| `/vulnerabilities/sqli/` | random path (e.g. `/intranet/records`) |
| `/vulnerabilities/exec/` | random path (e.g. `/ops/netcheck`) |
| SQLi `id` param | random (e.g. `item`, `entry`, `ref`) |
| `Submit` param | random (e.g. `go`, `run`) |
| cmd-injection `ip` param | random (e.g. `addr`, `host`, `target`) |
| `user_token` (CSRF field) | random (e.g. `nonce`, `form_sig`) |
| `security` cookie | **removed** (level is server-side); session cookie renamed off `PHPSESSID` (e.g. `APPSESS203`) |
| login fields `username` / `password` | random (e.g. `login` / `secret`) |
| `users` table | random (e.g. `credentials_store`, `personnel`) |
| columns `user_id`/`user`/`password`/`first_name`/`last_name` | random (e.g. `acct_no`/`handle`/`token_hash`/`contact`/`team`) |
| response template `ID: … First name: … Surname: …` | generic `"<LabelA>: … | <LabelB>: …"` with seeded labels |
| default creds `admin` / `password` | **non-default, randomized** (e.g. `j.reyes` / `lantern-copper-24`), discoverable in-app |
| MySQL backend (`information_schema`) | **SQLite** (`sqlite_master`) — same injection class, different introspection the model can't recall |

A per-instance manifest with the *concrete* mapping for a running container is written to
`/var/www/data/MUTATION.md` inside it:

```
docker compose exec dvwa cat /var/www/data/MUTATION.md
```

## The vulnerabilities (kept working, at medium)

Default `APP_LEVEL=medium`. Both are DVWA's medium logic, faithful:

- **SQL injection** (`target_app/app/modules/lookup.php`): quotes are escaped but the value
  is placed in an **unquoted numeric context**. String breakout (`' OR '1'='1`) fails;
  numeric / `UNION` injection works. The attacker must discover the renamed table/columns via
  `sqlite_master` (not `information_schema`) and dump the renamed credential store.
- **Command injection** (`target_app/app/modules/netcheck.php`): the medium blacklist strips
  `&&` and `;` only; `|`, `` ` ``, `$()` still pass, so `… | cat /etc/passwd` succeeds after the
  attacker adapts away from `;`.

`APP_LEVEL=low` gives the trivial variants (raw quote breakout / no shell filter) if needed.
There is intentionally no PDO-prepared "impossible" level — the target must stay exploitable.

## How to generate / reproduce an instance

Mutation happens at **container boot** (strongest form of Option C — per-deploy, not baked
into the image), via `target_app/docker-entrypoint.sh` → `bootstrap.php`.

- **Fresh random mutation every boot (default):** leave `BASTION_SEED` empty.
- **Reproducible instance:** set `BASTION_SEED=<anything>` (in `.env` or the environment).
  The same seed always yields the same paths/params/creds/schema.
- **Difficulty:** `APP_LEVEL=low|medium` (default `medium`).

```
BASTION_SEED=demo1 docker compose up --build dvwa
```

## Option A vs C status, and the C ceiling

- **A (fork & mutate): complete.** Every fingerprint above is stripped/renamed; verified by
  HTML grep, a live DeepSeek recognition probe (model does not recognize it and explicitly
  rules out DVWA), and working SQLi + cmdi exploits against the mutated endpoints.
- **C (randomize per deploy): complete at boot time**, not only build time. Because the app
  is **config-driven** (fixed PHP source reads a generated `instance.php`; only names vary),
  re-mutating per boot is robust rather than fragile — no PHP source templating. **Ceiling:**
  the *source* in `target_app/` is fixed, so a source leak reveals the *shape* (that there is
  a lookup module, a netcheck module, a config array). It does not reveal any specific
  instance's paths/params/creds/schema — those are seed-derived at boot and never committed.
  **Upgrade path if stronger isolation is ever wanted:** expand the word pools in
  `bootstrap.php`, add decoy/dead-end routes and extra vuln modules behind the seed, or
  template the module file names themselves. Not needed for demo contamination resistance.

## Integration notes (for the rest of the stack)

- **Service name `dvwa` and env `DVWA_URL` are intentionally unchanged.** They are
  internal-only (Docker network), never seen by the attacker or model, so keeping them avoids
  churning `actuator.py`, `log_store.py`, compose, and tests for zero de-fingerprinting gain.
- **`red_agent.py` is retargeted.** `authenticate()` now takes the discovered login `path`,
  reads the form's field names generically (fills by input *role*, carries the CSRF token),
  and detects success without DVWA-specific markers. Its prompt no longer hands it
  `admin/password`; it must find the (randomized) creds during recon — the in-app operator
  handbook documents them, as real demo/eval apps do.
- **Still DVWA-shaped, out of de-fingerprinting scope (the attacker never sees them):** the
  blue-side remediation/bootstrap tools `remediation_tools.py` (`patch_vuln` → `/security.php`),
  `bootstrap_dvwa.py`, and `actuator.py` (`rotate_secret`, session paths) still assume DVWA.
  They don't affect the red → Jev → blue-investigation flow being de-fingerprinted. Port them
  if/when the demo exercises the blue *remediation* path against this target.

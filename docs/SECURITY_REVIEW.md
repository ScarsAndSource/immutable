# Console security review

Scope: `src/immutable/server.py` and `web/`, the one-process demo console. The evidence
format and cryptography are covered in `docs/THREAT_MODEL.md`, not here.

The console runs student code and holds the seat's key on a machine the student uses, so
the question is who else can reach it.

| # | Finding | Risk | Fix |
|---|---|---|---|
| 1 | CORS `*`, no auth, no Host check, POST not content-type checked | Any web page open in the browser, or DNS rebinding, could call `/api/student/run` and execute code | `websec.check`: loopback Host with our port, session cookie (HttpOnly, SameSite=Strict), Origin and Sec-Fetch-Site checks, JSON-only POST, no CORS headers |
| 2 | Path checks used `startswith` | A sibling directory such as `workspace-evil` passed the check | `Path.is_relative_to`; `policy.is_relpath` on every name; dotfiles and unknown extensions not served |
| 3 | Unbounded request bodies, no socket timeout | Memory exhaustion, stalled connections | 2 MiB body cap (413), 1 MiB editor file cap, 15 s socket timeout, rate limits on run, save and tamper-lab |
| 4 | Assessor, witness and tamper-lab endpoints always exposed | A student console reaches assessor functions | `--mode exam` refuses them; demo mode keeps them |
| 5 | UI loaded Tailwind, Google Fonts and Material Symbols from the internet | Offline demo fails; third-party code runs in the page | `scripts/vendor_web.py`, SHA-256 manifest, CSP `default-src 'none'` with `'self'` allowances |
| 6 | 13 `innerHTML` sites rendering server text; file names may contain `<` and `>` | Stored XSS in the assessor console through a hostile file name | `web/safe.js` (`html` tag escapes by default); `preflight.py` lists remaining sites |
| 7 | 500 responses returned `str(exc)` | Internal paths and messages leaked | Generic message, traceback to stderr; user-input errors return 400 |
| 8 | `api()` swallowed errors and fell back to demo data | A dead backend looked alive | Visible backend-down banner; fake fallback data removed |

## Still true

- CSP keeps `'unsafe-inline'` for scripts and styles because the page uses inline handlers and
  the Tailwind play script. Escaping in `safe.js` is therefore the real XSS defence.
- The cookie is not `Secure` (plain HTTP on loopback). Cookies are not port-scoped, so a
  different local service on another port could receive it; the Host and Origin checks, which
  include the port, are what stop it being used.
- Demo mode puts student, assessor and tamper-lab functions in one process by design. Use exam
  mode, or the file-based tools, for a real lab.
- The runner is a leash, not a cage (see `docs/LIMITATIONS.md`).
- Set `IMMUTABLE_CSP_REPORT_ONLY=1` to see CSP violations in the browser console without
  blocking anything while you tune it.

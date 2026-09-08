# Demo API fixtures

`api.mjs` contains invented presentation data. The capture pipeline serves the
actual, unchanged React application from `frontend/` through Vite and supplies
these responses from a separate HTTP server bound only to `127.0.0.1`. Dashboard,
connection, and log views receive real Server-Sent Events using the application's
normal API contracts. No router, account, subscription, or production secret is
read. Browser requests to other origins are blocked.

The traffic totals, latency values, engine versions, configuration-validation
response, and update state illustrate UI states; they are not measurements or
proof of a successful production operation. Documentation-only public IP ranges
are used for connection destinations. Source URLs and controller passwords are
absent.

When refreshing the demo after a product change, check these sources:

| Fixture | Application contract |
| --- | --- |
| General response shapes | `frontend/src/types.ts` |
| Engine names, native formats, capture modes, management support | `internal/app/engine_catalog.go` |
| Pages, actions, features | `internal/app/core.go` |
| Dashboard and connection events | `frontend/src/core-dashboard.ts`, `frontend/src/pages/ConnectionsPage.tsx` |
| Configuration document and validation response | `frontend/src/pages/RawConfigPage.tsx` |
| Routes and section tabs | `frontend/src/App.tsx`, `frontend/src/router.ts` |

Keep Mihomo YAML and sing-box JSON separate. The sing-box management fixture
intentionally disables proxy subscriptions, local rule lists, and Fake-IP capture
management, matching the engine catalog. The capture script checks advertised
capture modes against the Go source and fails if they diverge.

Run `npm run capture` from `docs/demo` after following the setup instructions in
the parent README. A successful run produces 28 PNGs and
`assets/ui/manifest.json`, including source revision, fixture hash, pinned browser
version, screenshot hashes and dimensions, observed API requests, and browser
error/overflow results. Unknown API requests fail the run so new application
requirements cannot silently become blank screenshots.

The script exercises proxy latency testing and selection, engine filtering,
native-config validation, tab switching, connection details and search, local
rule-list expansion, and desktop/mobile layouts. Visible validation success is a
simulated API response. All demonstration mutations stay within the temporary
fixture server and disappear when the capture process exits.

# research-fingerprints handoff

lane: new fingerprint modules (extends open PR #272, cockpit + gitea). untouched
in-flight worktrees and PRs #269-280 confirmed via `git worktree list` grep and
`gh pr diff` grep across every open PR's added files for candidate names.

added 4 modules in modules/recon/, following the existing woodpecker/gocd
version-exposure schema (medium severity, tags include fingerprint/version/recon):

## nextcloud-version-exposure.yaml
- probe: GET /status.php (nextcloud's own always-public status endpoint, no auth)
- marker: `"productname":"Nextcloud"` anded with presence of `"versionstring"`
- why unique: ownCloud is the sibling fork sharing the exact same status.php json
  schema (installed/maintenance/needsDbUpgrade/version/versionstring/edition/
  productname) but ships `"productname":"ownCloud"`. keying on the productname
  value, not just the schema shape, is what separates the two.
- version regex: `"versionstring"\s*:\s*"([^"]+)"` group 1
- real samples pulled live:
  - https://cloud.nextcloud.com/status.php -> versionstring "34.0.1"
  - https://demo1.nextcloud.com/status.php -> versionstring "34.0.0"
- dupe check: grep across modules/ and all worktrees/open PRs, no hit before this change
- residual risk: none identified for the productname anchor; status.php is
  unconditionally public by nextcloud design (used for update checkers), so this
  is correctly a fingerprint, not an auth-bypass, hence medium not high

## jellyfin-version-exposure.yaml
- probe: GET /System/Info/Public (jellyfin's own unauthenticated public info endpoint)
- marker: `"ProductName":"Jellyfin Server"` anded with presence of `"Version"`
- why unique: Emby is the ancestor jellyfin forked from and keeps the same
  /System/Info/Public path and json shape (LocalAddress/ServerName/Version/
  ProductName/OperatingSystem/Id), but reports `"ProductName":"Emby Server"`.
  the productname value is the load-bearing anchor, not the endpoint shape.
- version regex: `"Version"\s*:\s*"([^"]+)"` group 1
- real sample pulled live: https://demo.jellyfin.org/stable/System/Info/Public ->
  `{"LocalAddress":"...","ServerName":"Stable Demo","Version":"10.11.11",
  "ProductName":"Jellyfin Server",...}`
- dupe check: clean, no hit
- residual risk: I could not reach a live Emby instance to pull a real negative
  sample (both public demo hosts 404'd during this session); the Emby json shape
  used in the trap test is reconstructed from memory of Emby's public api docs,
  not independently re-verified live. if Emby ever renames the field or drops
  ProductName the trap test would need updating, but the detector's own anchor
  (positive match on the exact Jellyfin string) is unaffected either way.

## forgejo-version-exposure.yaml
- probe: GET /api/v1/version (same path forgejo inherited from gitea, the fork it's based on)
- marker: regex `"version"\s*:\s*"[^"]*\+gitea-[0-9]` on the body
- why unique: forgejo appends `+gitea-<compat-version>` to its own version string
  to advertise gitea api compatibility; vanilla gitea does not do this. verified
  against three distinct real gitea-family instances in this session:
  - codeberg.org (forgejo, the reference forgejo host) -> "15.0.0-156-02d7aaa8+gitea-1.22.0"
  - git.private.coffee (forgejo) -> "15.0.3+gitea-1.22.0"
  - gitea.com (official gitea, dev branch) -> "1.27.0+dev-521-g840e7c6a54" (no match, +dev not +gitea)
  - opendev.org (official gitea, stable release) -> "v1.26.2" (no match, no suffix at all)
  three real samples across two forks and two gitea build styles (dev vs release)
  confirm the +gitea- suffix is forgejo-specific, not a general gitea versioning artifact.
- version regex (full string, includes the +gitea- suffix as evidence of the
  compat pin): `"version"\s*:\s*"([^"]+)"` group 1
- dupe check: clean, no hit (PR #272 fingerprinted gitea by favicon hash, not
  forgejo, and did not touch this endpoint)
- residual risk: if forgejo ever drops the +gitea- compat suffix from its own
  version string in a future release this detector would false-negative on new
  forgejo but would not false-positive on gitea; fail-closed direction is safe

## immich-version-exposure.yaml
- probe: GET /api/server/version (immich's own unauthenticated version endpoint)
- marker: response header `access-control-allow-headers` containing
  `x-immich-session-token` (immich's custom auth header, advertised in its own
  cors preflight allow-list on every api response including this one), anded
  with body containing all of "major"/"minor"/"patch"
- why unique: the version body itself is generic
  (`{"major":3,"minor":0,"patch":1,"prerelease":null}`) and could be any small
  rest api, so it is not safe to key on alone; the cors header is immich-branded
  and present on every response from the real server, giving a structural anchor
  instead of a bare json-shape guess
- extraction: three separate json extractors (immich_major/immich_minor/
  immich_patch reading json paths major/minor/patch) since the engine's regex
  extractor takes a single capture group and can't concatenate three fields into
  one dotted version string; gjson multipath was considered but three named
  extractors match the multi-extractor precedent already in the tree (see
  modules/recon/docker-compose-exposure.yaml, harbor-api-exposure.yaml)
- real sample pulled live: https://demo.immich.app/api/server/version ->
  `{"major":3,"minor":0,"patch":1,"prerelease":null}` with header
  `access-control-allow-headers: x-immich-session-token, x-api-key,
  Authorization, Content-Type`
- dupe check: clean, no hit
- residual risk: this is a 4th module beyond the requested 2-3; cut it if the
  lane wants to stay tighter. the header marker is present unconditionally
  (it's set on cors preflight regardless of auth state), so this is correctly a
  fingerprint (medium), not an exposure claim

## tests
each module ships a dedicated test in internal/modules/ following the existing
*_exposure_test convention (package modules_test, a per-module run helper over
httptest + ParseYAMLModule + ExecuteHTTPModule, positive + negative subtests).
every case uses the exact real sample bytes captured live during research:

- nextcloud_version_exposure_test.go: real cloud.nextcloud.com body fires and
  extracts 34.0.1; ownCloud body (same schema, productname "ownCloud"), a
  generic status json, and a 404 do not fire
- jellyfin_version_exposure_test.go: real demo.jellyfin.org body fires and
  extracts 10.11.11; Emby body (ProductName "Emby Server"), a generic info
  json, and a 404 do not fire
- forgejo_version_exposure_test.go: real codeberg.org and git.private.coffee
  bodies fire and extract the full +gitea- version; real gitea.com dev build
  and opendev.org release (no +gitea- suffix) and a 404 do not fire
- immich_version_exposure_test.go: real demo.immich.app header+body fires and
  extracts major 3 / patch 1; a version body without the x-immich-session-token
  cors header, the header without a version body, and a 404 do not fire

## verify
```
export GO111MODULE=on GOTOOLCHAIN=local
go build ./... && go vet ./... && go test -count=1 ./...   # all green
~/go/bin/golangci-lint run                                 # 0 issues
```
the four new test funcs run 18 subtests total, all pass; full-repo test suite,
go vet, and golangci-lint all clean.

## not shipped
uptime-kuma, authelia, authentik, paperless-ngx, home assistant were scoped but
dropped: none exposes a clean unauthenticated version-bearing endpoint I could
verify live in this session (uptime-kuma has no public version api; authelia's
config/health endpoints don't carry version; paperless-ngx's api requires auth
for the endpoints that carry version; home assistant's manifest.json omits
version and its api requires a token). shipping any of those would mean
guessing at an endpoint instead of proving one, so left for a future pass with
more time to stand up local instances.

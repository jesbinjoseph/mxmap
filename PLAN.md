# MXmap India Expansion — Implementation Plan

Extend the MXmap pipeline to surface three new India-relevant signals (DMARC, DNSSEC, Hosting Sovereignty) plus a Phase 0 coverage fix that must precede the signal work. The plan follows the existing architecture: async DNS probes in `probes.py` emit `Evidence` objects, `classifier.py` aggregates them, and `pipeline.py` serializes results into `data.json` for the Leaflet frontend.

## High-Level Architecture Context

Current pipeline, important to preserve:

- **Stage 1 (`resolve.py`)** writes `municipality_domains.json` from BFS (`indian_municipalities.csv`) + Wikidata SPARQL + website scraping + `guess_domains()` + `overrides.json`. A domain is only accepted into a source bucket if `lookup_mx(domain)` succeeds. Entities with no MX on any candidate end up with `domain:""`, `source:"none"`, and become unknowns downstream.
- **Stage 2 (`pipeline.py` + `classifier.py`)** orchestrates `classify(domain)`, which runs 11 probes concurrently via `asyncio.gather` and aggregates `Evidence` into a `ClassificationResult` using `_aggregate` + `_rule_confidence`. Output fields are filtered through `_FRONTEND_FIELDS` for `data.min.json`.
- **Frontend (`index.html`)** reads `data.min.json`, colours each state by dominant provider category, and shows entities grouped by type in popups.

The new signals (DMARC, DNSSEC, hosting) are **posture signals**, not provider-classification signals. They must not distort `provider` or `confidence`. They get their own fields on the entity record, their own classification tiers (green/amber/red), and their own frontend surface. This keeps the two concerns (who hosts email vs how well the domain is configured) cleanly separated.

---

## Phase 0 — Coverage Diagnosis and Fix

### Root cause confirmed

`municipality_domains.json` already contains the diagnosis in plain sight:

- 130 entities have `"source": "none"` and `"domain": ""` — exactly the 130 unknowns in `data.json` counts.
- 18 entities have `"source": "guess"` with the `guess_only` flag.
- Only 32 entities are in `overrides.json`; the remaining 147 rely on Wikidata / scrape / guess.

Spot-checks of the 130 `"source":"none"` entries show:

1. **All 61 Districts in `indian_municipalities.csv`** are unknowns. `guess_domains(..., entity_type="District")` produces `{slug}.gov.in`, `{slug}.nic.in`, `{slug}.{state}.gov.in`, `{slug}.{state}.nic.in`. These mostly don't have MX records — the actual district NIC portals live at `{slug}.nic.in` but use a state MX, or at unguessable subdomains like `collector{district}.{state}.gov.in`. The acceptance rule in `resolve.py` (line 594: `mx = await lookup_mx(guess); if mx: sources["guess"].add(guess)`) is too strict for districts.
2. **Several states with no override** (Arunachal Pradesh #2, Haryana #8, Telangana #24, etc.) — `guess_domains` for State type only produces `{state_abbrev}.gov.in` / `{state_abbrev}.nic.in` / `{slug}.gov.in` / `{slug}.nic.in`. When these don't have MX records directly (many states route mail through a different domain like `dir.hr.nic.in`), the entity drops to "none".
3. **Large MCs without override** (Greater Hyderabad #1004, etc.) — `guess_domains` for MC tries `{slug}.gov.in`, `{slug}.nic.in`, `{slug}mc.gov.in`, `{slug}nmc.gov.in`, `{slug}municipal.gov.in` but the actual domain (`ghmc.gov.in` for Greater Hyderabad) doesn't follow any of these patterns.
4. **`fetch_wikidata()` returns nothing for any of the 179 entities.** `municipality_domains.json` shows `"wikidata": []` on every non-override row — the SPARQL query filters by `wdt:P4890 ?lgdCode`, which most Indian state/district Wikidata items don't carry. The CSV LGD codes (1, 29, 500, 1001…) don't match real LGD codes in Wikidata either; they are synthetic per `indian_municipalities.csv`.
5. **Website scrape never fires** for entities missing a Wikidata `website` — the only entrypoint for scrape is `website_domain = url_to_domain(m.get("website", ""))`, which is empty without Wikidata.

### Fix strategy

**0.1 — Expand `overrides.json` to cover all Tier-1 entities (fast win).**
Target: zero unknowns for the 36 States/UTs and the ~56 Municipal Corporations. Populate abbreviations, well-known MC domains (`ghmc.gov.in`, `nmcnagpur.gov.in`, `imc.gov.in`, `lmc.up.nic.in`, `jaipurmc.org`, `pmcindore.mp.gov.in`, `amc.gov.in`, `kmc.up.nic.in`, etc.) from authoritative sources (state portals, LGD directory). Write this into `overrides.json` with `reason` fields. Overrides already short-circuit `resolve_municipality_domain()` at line 549.

**0.2 — Relax the District guess policy.**
Districts typically don't have their own MX but their mail flows through a state-level NIC MX. Two options:

- **(a) Accept guesses with A/AAAA records even without MX**, with a new `flags:["no_mx_uses_parent"]` marker. Downstream `classify()` sees an empty MX list → currently returns INDEPENDENT / provider=`independent`. Needs matching tweak in classifier to recognise "has A record on `.gov.in` + no MX" as a weak NIC signal.
- **(b) Add parent-zone MX fallback**: if a district `{slug}.{state}.nic.in` has no MX but its parent `{state}.nic.in` does, record the district domain + a flag `mx_from_parent_zone`. This preserves the domain-per-entity mapping while letting classification re-use the parent's signals.

Recommended: **(b)**. Implement as an extra pass inside `resolve_municipality_domain()` after the existing source loop.

**0.3 — Add a scraper entry point for entities without a Wikidata website.**
For any entity with `source:"none"` after the normal flow, try the `guess_domains()` candidates as website URLs and run `scrape_email_domains()` on them. Many `.gov.in` landing pages publish contact emails even when the zone itself has no MX. This reuses existing code paths (`build_urls`, `extract_email_domains`) and costs nothing for already-resolved entities.

**0.4 — Replace the Wikidata SPARQL probe with LGD-directory lookups.**
The current SPARQL is effectively dead weight for India. Defer replacement (flagged as follow-up below) but keep the stub so the code path is exercised in tests. Add an optional adapter `lgd_directory.py` behind a feature flag; do not block on this.

**0.5 — Add a baseline coverage test.**
New test `tests/test_data_validation.py::test_coverage_regression` — once `overrides.json` is expanded and `municipality_domains.json` regenerated, assert `unknown_count <= N` where N is the freshly established baseline. This turns the diagnosis into a guardrail.

### Phase 0 deliverables

- `overrides.json` expanded from 32 to ~80 entries covering all States/UTs and top MCs.
- `src/mail_sovereignty/resolve.py` — parent-zone MX fallback for Districts + fallback website scrape when Wikidata has no website.
- `src/mail_sovereignty/classifier.py` — weak-NIC rule for A-record-only `.gov.in/.nic.in` domains.
- `tests/test_resolve.py` — new fixtures for parent-zone fallback, no-website scrape.
- `tests/test_data_validation.py` — coverage regression assertion.

### Phase 0 exit criteria

- `data.json` `counts.unknown` reduced from 130 to **< 30** (target: < 15 after overrides).
- All 36 States/UTs resolved with `confidence: high` or `medium`.
- All 56 MCs resolved (override or scrape/guess).
- Remaining unknowns are Districts where no plausible parent zone exists — these are acceptable and documented.

---

## Phase 1 — DMARC Policy

### Current state

`probes.py::probe_dmarc` already queries `_dmarc.<domain>` TXT but only matches against `sig.dmarc_patterns` for provider classification (which no Indian provider uses meaningfully). The raw DMARC record is not preserved anywhere in `data.json`.

### New probe module

Add `src/mail_sovereignty/posture.py` — a new module for posture-only signals that don't feed `classifier.py`. Keep it separate so adding them doesn't change provider weights (`WEIGHTS` must keep summing to 1.0, which `tests/test_probes.py::TestWeights` enforces).

`posture.py` exports:

```
async def probe_dmarc_posture(domain: str) -> DmarcPosture | None
```

Parses `p=`, `sp=`, `pct=`, `rua=`, `ruf=`, `fo=`, `adkim=`, `aspf=` from the TXT record. Returns a pydantic model `DmarcPosture` with fields:

| field             | type                    | notes                                                     |
|-------------------|-------------------------|-----------------------------------------------------------|
| `present`         | `bool`                  | TXT record found at `_dmarc.<domain>`                     |
| `policy`          | `Literal["none","quarantine","reject"] \| None` | from `p=`                              |
| `subdomain_policy`| `Literal[...] \| None`  | from `sp=` (falls back to `policy` per RFC 7489)          |
| `pct`             | `int \| None`           | from `pct=` (default 100)                                 |
| `rua`             | `list[str]`             | reporting URIs                                            |
| `ruf`             | `list[str]`             | forensic URIs                                             |
| `tier`            | `Literal["green","amber","red","missing"]` | compliance tier                       |
| `raw`             | `str`                   | original TXT content                                      |

### Tiering rules

- **green**: `p=reject` and `pct=100` (or pct absent).
- **amber**: `p=quarantine`, OR `p=reject` with `pct<100`.
- **red**: `p=none`, OR record present but malformed (missing `p=`).
- **missing**: no `_dmarc.<domain>` TXT record at all.

### Data model additions

In `pipeline.py::_serialize_result`, call `probe_dmarc_posture(domain)` alongside existing probes (gather it inside `classify()` and return through the `ClassificationResult`, OR run it as a separate coroutine in `pipeline.run()` after classification — recommended the latter, so `ClassificationResult` stays stable). Add to the per-entity output record:

```json
"dmarc": {
  "present": true,
  "policy": "reject",
  "subdomain_policy": "reject",
  "pct": 100,
  "rua": ["mailto:dmarc@example.gov.in"],
  "ruf": [],
  "tier": "green",
  "raw": "v=DMARC1; p=reject; rua=mailto:..."
}
```

Add `"dmarc"` to `_FRONTEND_FIELDS` in `pipeline.py`. For the min JSON, drop `raw` to save bytes.

### Classification impact

**None.** DMARC stays a posture-only field. The existing weak DMARC match for MS365 (`dmarc_patterns=("rua.agari.com",)`) stays in `probe_dmarc()` so provider weights don't change.

### Frontend surfacing

In `index.html`:

- **Popup detail rows** — add a DMARC row next to each entity in the state popup (lines 517–523 of `index.html`). Small coloured dot (green/amber/red/gray) + policy label. Keep compact on mobile.
- **Legend & filter** — add a small toggle in the legend control that recolours states by DMARC tier instead of provider category. Reuse `getDominantColor()` pattern; parameterise it on a field-selector function. Color scheme: green=`#4ade80`, amber=`#fbbf24`, red=`#ef4444`, gray=`#9ca3af`.
- **Aggregate counts** — extend the legend counts block with DMARC tier tallies.

### Dependencies

No new Python packages. Parsing DMARC is a simple `;`-split. Reuse `resolve_robust()` from `dns.py`.

### Tests

- `tests/test_posture.py` (new) — DMARC parser fixtures: valid `p=reject`, `p=quarantine`, `p=none`, missing record, malformed record, multi-record (RFC says first wins), quoted-string strings with escaped semicolons. Mock `resolve_robust`.
- `tests/test_pipeline.py` — assert `dmarc` field present in serialized output; min-JSON excludes `raw`.

---

## Phase 2 — DNSSEC Status

### New probe

In `src/mail_sovereignty/posture.py`:

```
async def probe_dnssec(domain: str) -> DnssecStatus
```

Two complementary checks:

1. **DS record presence at the parent zone.** Query `domain` with `rdtype=DS`. Presence of a DS record proves the parent has delegated DNSSEC signing.
2. **AD-flag validation.** Re-query the A record (or MX) with `dnssec=True` / EDNS DO bit set, asking a validating resolver. Use Cloudflare `1.1.1.1` (already in `dns.py` resolver list). Check `answer.response.flags & dns.flags.AD`.

Return model `DnssecStatus`:

| field          | type                                          | notes                                    |
|----------------|-----------------------------------------------|------------------------------------------|
| `ds_present`   | `bool`                                        | DS record exists at parent               |
| `ad_validated` | `bool`                                        | validating resolver set AD flag          |
| `algorithm`    | `int \| None`                                 | DNSKEY algorithm number if present       |
| `tier`         | `Literal["signed_validated","signed_unvalidated","unsigned","error"]` | |

### Tiering rules

- **signed_validated**: DS present AND AD flag set → fully DNSSEC-protected.
- **signed_unvalidated**: DS present but AD flag missing → misconfiguration or broken chain.
- **unsigned**: DS absent → no DNSSEC.
- **error**: resolver errors, SERVFAIL on DS, etc.

### Why DNSSEC matters for India

MeitY's GIGW 3.0 mandates DNSSEC for `.gov.in`. The map will show which states/districts actually comply. Expect most unsigned today; the map itself is the advocacy.

### Data model additions

```json
"dnssec": {
  "ds_present": true,
  "ad_validated": true,
  "algorithm": 13,
  "tier": "signed_validated"
}
```

Add `"dnssec"` to `_FRONTEND_FIELDS`.

### Architectural trade-off: validating resolver

The `dnspython` library does not perform full DNSSEC validation itself. Two implementation options:

- **(a) Trust a validating upstream resolver.** Send queries with EDNS `DO=1` to `1.1.1.1` (which validates), check the `AD` flag. This is what 95% of DNSSEC monitoring tools do. Fast, no extra deps.
- **(b) Full chain validation.** Use `dnspython`'s `dns.dnssec.validate()` helpers to walk from the root trust anchor. Slower, requires the root KSK, more code, much higher test-fixture burden.

**Recommendation: (a)**. Document clearly in the probe docstring that AD-flag trust is conditional on the upstream resolver. For the deterministic tests, mock the `dns.flags.AD` bit on the response.

### Frontend surfacing

Same pattern as DMARC:

- Popup row per entity.
- Legend toggle to recolour by DNSSEC tier.
- Aggregate counts in legend.

### Dependencies

`dnspython>=2.8.0` already present — supports DS queries and EDNS DO. No new deps.

### Tests

- `tests/test_posture.py::TestDnssec` — fixtures for DS-present/AD-set, DS-present/AD-unset, NXDOMAIN on DS, SERVFAIL. Mock `resolve_robust` to return mock answers with `.response.flags` and mock DS rdata.

---

## Phase 3 — Hosting Sovereignty (IP → ASN → Country → Category)

This is the largest phase. Two inputs: the domain's A/AAAA records (web host) and the MX hosts' A records (mail host). Both get resolved and mapped.

### New probe

In `src/mail_sovereignty/posture.py`:

```
async def probe_hosting(domain: str, mx_hosts: list[str]) -> HostingPosture
```

For each of:

- `domain` A + AAAA (the web server — where citizens reach the site).
- each MX host's A + AAAA (the mail server — separately, because they may differ).

Resolve IPs, then for each unique IP look up ASN + country code + organisation name. Classify into one of these hosting tiers:

- `nic_nkn` — ASN 4758 (NIC) or 9829 (NKN/BSNL-Gov).
- `indian_gov_dc` — ASN list: SIFY-Gov, NICSI, state data centres (NDC Delhi, Kerala State Data Centre, etc.). Maintain in `signatures.py` as `INDIAN_GOV_DC_ASNS: dict[int, str]`.
- `indian_private_cloud` — existing `INDIAN_ISP_ASNS` entries minus NIC/NKN: CtrlS (24186), Yotta (133982), Sify (133275), ESDS (135647), Airtel (9498), Jio (55836), Tata (17762/4755).
- `foreign_cloud` — AWS (16509, 14618), GCP (15169, 396982), Azure (8075, 8068), Cloudflare (13335), OVH (16276), Oracle (31898), Akamai (20940), Fastly (54113), Hetzner (24940), DigitalOcean (14061). Also match by country code: any non-IN country is `foreign_cloud` if not otherwise classified.
- `unknown` — ASN lookup fails or IP resolves nowhere known.

### Data source choice — architectural trade-off

Three viable sources. Pick **one primary + one fallback**:

| source              | pros                                                    | cons                                                         |
|---------------------|---------------------------------------------------------|--------------------------------------------------------------|
| Team Cymru DNS-whois (already used in `probe_asn`) | no deps, no auth, free, deterministic for tests    | TXT format quirks; rate-limits (~100 qps); country is 2-letter only; ASN name sometimes stale |
| MaxMind GeoLite2 ASN+Country mmdb | offline, millisecond lookups, batch-friendly, very accurate     | 2.4 MB + 6 MB mmdb files to ship; MaxMind EULA requires monthly update pipeline; needs `maxminddb` Python package |
| ipinfo.io API       | rich org classifications (AWS-region-level)             | paid tier needed for production volume; rate-limits; network-dependent |

**Recommendation:**

- **Primary: MaxMind GeoLite2-ASN + GeoLite2-Country mmdb.** The deterministic, offline lookup is a huge win for test reliability and CI speed. Ship the mmdb files outside git (download in a CI step) or vendor them at a pinned version.
- **Fallback: Team Cymru DNS-whois.** Already implemented in `probe_asn`. If the mmdb file is missing or an IP isn't in it (rare), fall through.
- **Do not adopt ipinfo.** Paid, network-dependent, no benefit over MaxMind for the classification granularity this project needs.

New dependency: `maxminddb>=2.5.1` in `pyproject.toml`.

Add a small helper `src/mail_sovereignty/geoip.py`:

```
class GeoIPLookup:
    def __init__(self, asn_db: Path | None, country_db: Path | None): ...
    def lookup(self, ip: str) -> IpInfo | None: ...  # returns (asn, asn_org, country)
```

Load lazily, cache per-process. If the mmdb files aren't present (dev setup without download), fall back to Team Cymru.

### Data model additions

```json
"hosting": {
  "web": {
    "ips": ["164.100.14.32"],
    "asns": [{"asn": 4758, "org": "National Informatics Centre", "country": "IN"}],
    "tier": "nic_nkn"
  },
  "mail": {
    "ips": ["164.100.2.4"],
    "asns": [{"asn": 4758, "org": "National Informatics Centre", "country": "IN"}],
    "tier": "nic_nkn"
  },
  "tier": "nic_nkn"
}
```

`hosting.tier` is the overall sovereignty tier, computed as the worst of `web.tier` and `mail.tier` (where `foreign_cloud > indian_private_cloud > indian_gov_dc > nic_nkn` in "concern order"). Reason: a site hosted on NIC but mail on Microsoft 365 is still sovereignty-relevant; both need visibility.

Add `"hosting"` to `_FRONTEND_FIELDS`. For `data.min.json`, strip the nested `ips` list (only keep tier + summary).

### Classification impact

**None on `provider`**, which already uses MX-pattern + SPF-include + ASN matching to decide WHO runs the mail. Hosting sovereignty is an independent view ON the same data.

Note the **overlap with `probe_asn`**: that probe runs Team Cymru on MX IPs to feed provider classification. The new hosting probe runs on domain A records + MX host A records and expands ASN categorisation. Share a single IP → ASN cache per run to avoid double lookups. Factor the shared logic into `geoip.py::lookup_asn()` and have both `probe_asn` (existing, in `probes.py`) and `probe_hosting` (new, in `posture.py`) call through it.

### Frontend surfacing

- **Third legend mode**: user can toggle legend between Provider / DMARC / DNSSEC / Hosting. Implement as a single radio group in the legend control.
- **Hosting colours**: nic_nkn=`#16a34a` (deep green), indian_gov_dc=`#65a30d` (olive), indian_private_cloud=`#f59e0b` (amber), foreign_cloud=`#dc2626` (red), unknown=`#9ca3af` (gray).
- **Popup detail rows**: add a Hosting row (web + mail separately if they differ).

### External dependencies

- Python: `maxminddb>=2.5.1` added to `pyproject.toml` deps.
- Data: GeoLite2-ASN.mmdb + GeoLite2-Country.mmdb. Document download path in README under a new `data/geoip/` directory; add to `.gitignore`. Add a CI pre-step `download-geoip.sh` that pulls the mmdb files from MaxMind (requires a free account key — store as repo secret `MAXMIND_LICENSE_KEY`).
- Offline/deterministic tests: ship tiny fixture mmdb files generated with `mmdbwriter` covering the handful of IPs used in tests, under `tests/fixtures/geoip/`. Point the test configuration at these via an env var or conftest fixture.

### Tests

- `tests/test_geoip.py` — loading, lookup, missing-file fallback, IPv6.
- `tests/test_posture.py::TestHosting` — parameterised over NIC IP, AWS IP, Cloudflare IP, unknown IP; assert tier classification. Mock GeoIPLookup rather than using fixture mmdb in unit tests; use real fixture mmdb in a separate integration test.
- `tests/test_pipeline.py` — `hosting` field present, tier derivation worst-of-web-and-mail is correct.

---

## Critical Files to Touch (by phase)

### Phase 0 — Coverage fix

- `/private/tmp/mxmap/overrides.json` (data, expand to ~80 entries)
- `/private/tmp/mxmap/src/mail_sovereignty/resolve.py` (parent-zone fallback, scrape-without-wikidata)
- `/private/tmp/mxmap/src/mail_sovereignty/classifier.py` (weak NIC rule for A-only `.gov.in`)
- `/private/tmp/mxmap/tests/test_resolve.py` (fixtures for new paths)
- `/private/tmp/mxmap/tests/test_data_validation.py` (coverage regression guardrail)

### Phase 1 — DMARC

- `/private/tmp/mxmap/src/mail_sovereignty/posture.py` (new file — `DmarcPosture`, `probe_dmarc_posture`)
- `/private/tmp/mxmap/src/mail_sovereignty/models.py` (export `DmarcPosture` if preferred here)
- `/private/tmp/mxmap/src/mail_sovereignty/pipeline.py` (call probe, add field to output + `_FRONTEND_FIELDS`)
- `/private/tmp/mxmap/index.html` (popup row + legend toggle)
- `/private/tmp/mxmap/tests/test_posture.py` (new)

### Phase 2 — DNSSEC

- `/private/tmp/mxmap/src/mail_sovereignty/posture.py` (add `DnssecStatus`, `probe_dnssec`)
- `/private/tmp/mxmap/src/mail_sovereignty/dns.py` (may need a helper that preserves the `AD` flag on the response; current `resolve_robust` returns only `Answer`, which already carries `.response`, so usually no change)
- `/private/tmp/mxmap/src/mail_sovereignty/pipeline.py` (call probe, add field)
- `/private/tmp/mxmap/index.html` (popup row + legend toggle)
- `/private/tmp/mxmap/tests/test_posture.py` (extend)

### Phase 3 — Hosting

- `/private/tmp/mxmap/src/mail_sovereignty/geoip.py` (new — shared IP → ASN/country)
- `/private/tmp/mxmap/src/mail_sovereignty/signatures.py` (`INDIAN_GOV_DC_ASNS`, `FOREIGN_CLOUD_ASNS` dicts)
- `/private/tmp/mxmap/src/mail_sovereignty/posture.py` (`HostingPosture`, `probe_hosting`)
- `/private/tmp/mxmap/src/mail_sovereignty/probes.py` (refactor `probe_asn` to call `geoip.lookup_asn`)
- `/private/tmp/mxmap/pyproject.toml` (add `maxminddb`)
- `/private/tmp/mxmap/index.html` (hosting legend mode + popup rows)
- `/private/tmp/mxmap/tests/test_geoip.py` (new)
- `/private/tmp/mxmap/tests/test_posture.py` (extend)

---

## Architectural Trade-offs Summary

1. **Posture module vs. reusing classifier evidence chain.** Chose a separate `posture.py` + dedicated fields on the entity record (not `Evidence` objects) so that (a) `WEIGHTS` still sums to 1.0, preserving the existing test invariant; (b) posture signals never accidentally shift the provider vote; (c) frontend can toggle legend modes without reinterpreting evidence.

2. **DNS-only vs. HTTP probing.** Stay DNS-only for this release. All three new signals are expressible in DNS (DMARC TXT, DS/AD flag, A+AAAA). Adding HTTPS probing (TLS grade, GIGW headers, certificate issuer) would triple probe time and bring SSL library version concerns. Defer.

3. **GeoLite2 vs. Team Cymru vs. ipinfo.** GeoLite2 primary (offline, deterministic, licensed for use with monthly redistribution), Team Cymru fallback (already in code), no ipinfo (paid, no upside). Accept the operational cost of a CI step that refreshes the mmdb monthly.

4. **DNSSEC — AD-flag trust vs. full chain validation.** Trust the validating resolver (`1.1.1.1`). A full chain validator requires root-KSK bootstrap and tripled code complexity; the accuracy delta is marginal for a visualisation project.

5. **Domain resolution — expand overrides vs. build an LGD directory scraper.** Expand overrides for this release (fast, precise, reviewable via `reason` field), defer the LGD scraper (fragile, requires parsing a gov portal) to a follow-up. Document the 32 → 80 override expansion in the commit.

6. **Districts with no direct MX.** Parent-zone fallback rather than dropping them. Records the ACTUAL district domain so DMARC/DNSSEC/hosting probes still run on the correct subdomain, while classification inherits provider from the state mail zone.

---

## Out of Scope (Follow-ups, not plan items)

Explicitly deferred from the earlier brief; these are stubs for later plans, not this one:

- **TLS grading** (SSL Labs-style cipher/version/HSTS scoring). Requires HTTPS handshake probing — a whole new probe family.
- **GIGW compliance headers** (CSP, X-Frame-Options, Referrer-Policy, cache-control). Requires HTTP GET with header capture.
- **IPv6 reachability.** AAAA presence is already captured in Phase 3 hosting; a full IPv6-preferred-ordered transit check is out of scope.
- **Nameserver concentration** (e.g. "45% of `.gov.in` delegations terminate on four NIC NS — single point of failure"). Interesting map, but requires NS graph aggregation rather than per-entity signals.
- **LGD-directory integration as a resolve source.** Replace/augment Wikidata SPARQL with live LGD lookups. Separate project.
- **Frontend filter UI** (e.g. "show only entities with DMARC=red"). The per-mode legend recolouring in Phase 1–3 gives a visual filter; a checkbox filter panel is a follow-up UX pass.
- **Additional provider signatures** (Zoho, Rackspace India, Microsoft GCC India sovereign cloud). Orthogonal to posture signals.

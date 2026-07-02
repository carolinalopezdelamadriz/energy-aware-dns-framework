# Issues Log — Energy-Aware DNS Framework

Short log of problems found while building and testing the framework, and how
they were fixed. Kept for: (1) explaining progress to the TFG tutor, and
(2) reuse in the memoria (Metodología/Implementación/Discusión chapters).

---

## Issue 1: DoQ resolution returned 0 bytes

**Problem.** Early DoQ tests captured 0 bytes / failed queries instead of a
real resolution.

**Cause.** The framework was trying multiple DoQ resolvers (cloudflare,
google, quad9) inside the same run. Mixing resolvers meant failed handshakes
and retransmissions from unreachable/misbehaving resolvers polluted the
capture, and some resolvers simply didn't respond reliably from the test
network.

**Fix.** Fixed the framework to a single DoQ resolver per run (`quad9` by
default, via `--doq-resolver`). This keeps the PCAP clean and gives
consistent, non-zero byte counts.

**Status:** Fixed.

---

## Issue 2: Carbon model constants were unjustified placeholders

**Problem.** `cfp.py` used made-up values for energy-per-byte and CO2-per-kWh,
with no source.

**Fix.** Replaced with literature-backed values: energy intensity from the
Sustainable Web Design Model v4 (network segment, 0.059 kWh/GB), and grid
carbon intensity from CNMC's official Spanish electricity mix (0.283 kgCO2/kWh).

**Status:** Fixed.

---

## Issue 3: PCAP vs CDP overhead came out negative for several sites

**Problem.** For some sites (wikipedia, amazon, youtube...), the framework
reported CDP (browser-reported bytes) as *larger* than PCAP (real network
capture), which shouldn't be possible — PCAP should always capture at least as
much as CDP sees.

**Cause.** CDP counts the full size of resources served from disk cache or a
Service Worker, even though those bytes never actually crossed the network on
that page load — so they never show up in the PCAP.

**Fix.** `browser.py` now reads the `fromDiskCache`/`fromServiceWorker` flags
CDP provides and splits the byte total into `network_bytes` (comparable to
PCAP) vs `cached_bytes`. The overhead calculation in `web_experiment.py` now
uses `network_bytes`.

**Status:** Fixed, pending re-validation on a fresh pilot run.

---

## Issue 4: `chrome://new-tab-page` resources counted as site traffic

**Problem.** Some sites (worst case: wikipedia, 94% of reported bytes) had
most of their "traffic" coming from Chrome's own internal new-tab-page
resources, not the actual website.

**Cause.** With headless mode + a fresh browser profile, Chrome's first tab is
`chrome://new-tab-page/`. Network logging starts as soon as the browser opens,
before the real navigation happens, so the new-tab-page's own resources (built
into the browser, never sent over the network) get logged and counted
alongside the site's real traffic.

**Fix.** `browser.py` now ignores any resource whose URL isn't `http://` or
`https://` (drops `chrome://`, `data:`, etc.).

**Status:** Fixed, pending re-validation on a fresh pilot run.

---

## Issue 5: CDP still noticeably higher than PCAP for amazon/github/youtube

**Problem.** Even after Issues 3 and 4, some sites kept showing CDP totals
above PCAP, which is physically impossible — PCAP should always capture at
least as much as CDP sees. Initially seen as a gap for amazon/github (amazon:
5.2 MB CDP vs 2.5 MB PCAP); after re-validating on a fresh 10-site pilot with
real captures, it showed up as outright *negative* overhead for github
(-26.7%) and youtube (-72.9%).

**Cause (confirmed).** `analyzer.py` summed PCAP bytes with a regex over
`tcpdump`'s default text output, matching the `length N` field it prints for
protocols it can decode. For encrypted QUIC packets, `tcpdump` prints
`quic, protected` with **no length field at all**, so every QUIC/HTTP-3
packet was silently excluded from the byte count. Confirmed on the actual
capture: of 5919 packets in the youtube PCAP, 3125 were `quic, protected` and
contributed 0 bytes to the total, even though the file itself was ~5 MB.
Since YouTube and GitHub both serve heavily over HTTP/3, their totals came
out undercounted below the CDP figure.

**Fix.** All four `analyzer.py` functions (`analyze_total_bytes`,
`analyze_dns_bytes`, `analyze_https_bytes`, `analyze_quic_bytes`) now run
`tcpdump -e` and sum the Ethernet frame length printed after `ethertype`
(`ethertype IPv4 (0x0800), length N:`), which is always present regardless of
which protocol dissector `tcpdump` used for the rest of the line. Verified
against `analyze_quic_bytes` (used for the DoQ DNS measurements): 0 packets
were affected across the pilot's 10 DoQ captures, so the DNS protocol
comparison itself was never wrong — only the aggregate web PCAP total.

**Methodology note.** The new method counts the full frame (Ethernet + IP +
TCP/UDP headers + payload) instead of just the L4 payload as before, so byte
totals are consistently somewhat higher on both the DNS and web side than in
any run before 2026-07-01. Numbers from earlier runs are not directly
comparable to runs after this fix.

**Status:** Fixed and re-validated on a fresh real (non-synthetic) 10-site
pilot — no negative overhead in any site after the fix.

---

## Issue 6: permission errors after running with `sudo`

**Problem.** `--mode analyze` failed with a permission error when run without
`sudo` right after a `--mode batch` run.

**Cause.** `tcpdump` needs `sudo`, so the batch run created `results/` files
owned by `root`; the later analyze step (without `sudo`) couldn't write there.

**Fix.** Run `--mode analyze` with `sudo` too, or `sudo chown -R $USER results/`
after each batch.

**Status:** Workaround in place — superseded by Issue 9 (root cause: `sudo`
wasn't actually needed in the first place).

---

## Issue 7: Web PCAP capture picks up unrelated background traffic

**Problem.** Some sites showed wildly inflated overhead with no plausible
site-side explanation: wikipedia showed ~9000% overhead (7 MB PCAP vs 79 KB
CDP, even though the CDP profile only listed 6 legitimate resources for
wikipedia.org's minimal portal page) in one pilot run, and twitter/x.com
showed ~1735% overhead in another.

**Cause.** `start_capture()` for the web experiment uses a fixed filter
(`port 80 or 443 or 53 or 853`) that isn't scoped to the visited site's IP
addresses — unlike the DNS experiment, which does scope its filter to the
resolver host via `_build_host_filter`. Inspecting the offending PCAPs
confirmed it: the wikipedia capture contained thousands of packets to Google/
Microsoft/Cloudflare IPs that have nothing to do with wikimedia.org, and the
twitter capture had 35k+ packets to a single unrelated Google IP. Any other
app on the machine using HTTPS/DNS during the ~20 second capture window
(sync clients, other browser tabs, this very terminal session, etc.)
contaminates the "site" measurement.

**Decision.** Scoping the capture per-site is hard in general (a page loads
resources from dozens of dynamically-discovered third-party/CDN domains that
aren't known before the capture starts), and per-process filtering on macOS
would need extra tooling beyond `tcpdump`. Given the thesis deadline, chose a
manual mitigation instead of a code fix: close background network apps
before running the full batch. With 10 sites per category instead of 1 (as
in the pilot), a single noisy outlier has 10x less influence on category
averages.

Recurred at full 100-site scale (see Issue 10): the same background source
(one Google IP) showed up with heavy, sustained traffic in 11 of 99 web
captures spread across the whole ~4 hour run, confirming this isn't rare.
Issue 10's automated flagging in `run_analysis.py` now catches the worst
cases statistically instead of relying on manual review.

**Status:** Open / accepted as a documented limitation (mitigated, not
eliminated, by Issue 10's outlier flagging). Worth a mention in the memoria's
Limitaciones section.

---

## Issue 8: Per-site plots became unreadable at 100-site scale

**Problem.** The original `run_analysis.py` plotted one bar per site (web
traffic comparison, PCAP/CDP ratio, and the equivalent dashboard panels).
This was fine for the 5-10 site pilots but would render as ~100 illegible
bars/labels once the full `sites_100.csv` batch runs.

**Fix.** Redesigned the web-traffic figures to aggregate by category (10
categories, fixed regardless of how many sites feed each one) instead of by
individual site:
- `fig_web_overhead_scatter.png` — one point per site, colored by category,
  scales to any number of points.
- `fig_web_bytes_by_category.png` / `fig_web_overhead_by_category.png` —
  box plots per category instead of one bar per site.
- `fig_cfp_by_category.png` — new plot; CO₂ per category with min/max error
  bars (previously CO₂ only appeared in table cells, never visualized).

`summary.md` now shows a 10-row category table plus top-10 overhead/CO₂
outlier tables instead of a table with one row per site; full per-site detail
moved to `web_site_summary.csv`. Verified against both the real pilot and a
synthetic 100-site dataset before relying on it for the full batch.

**Status:** Fixed.

---

## Issue 9: `sudo` assumed necessary, actually unneeded on this machine

**Problem.** Issue 6 (above) documented a `sudo`-related permission problem
on the assumption that `tcpdump` requires `sudo` to capture packets.

**Correction.** On this machine, `tcpdump` already has BPF device permissions
configured (likely from a prior Wireshark/ChmodBPF install) and captures
packets fine as a regular user — verified directly (`tcpdump -i en0` outside
of `sudo` captured live traffic with no error). Running the batch with
`sudo -E` is therefore unnecessary and actively counterproductive: it makes
every file under `results/` for that run owned by `root`, which is what
caused Issue 6 in the first place.

**Fix.** Drop `sudo` from the batch command entirely; run
`python3 src/main.py --mode batch ...` as the normal user. `--mode analyze`
then works without any permission workaround.

**Status:** Fixed (methodology corrected; no code change needed).

---

## Issue 10: Headless-browser bot detection + background noise skewed the full 100-site run

**Problem.** Interpreting the first full 100-site batch (`results/20260702_004307`),
category-level average overhead was absurd for several categories (Health
10,524%, Standards 9,474%, Banking 6,648%), and the "highest overhead sites"
table was dominated by values like 90,948% (`ieee`) and 83,993% (`pubmed`) —
clearly not real network overhead.

**Cause 1 — anti-bot detection (9 of 99 sites).** Checked the offending
sites' CDP profiles: `ieee.org` and `sabadell` returned pages of ~500-600
bytes (just a `Document` + `favicon.ico`), nowhere near a real homepage.
Confirmed with `curl` using a `HeadlessChrome` user agent: `ieee.org` returns
HTTP 418 with a JS bot-fingerprinting challenge page (`TSPD` cookie,
Radware/F5-style), `bancosabadell.com` redirects to an Akamai "Access Denied"
edge response, `pubmed.ncbi.nlm.nih.gov` returns HTTP 403. These sites detect
headless/automated Chrome (via `navigator.webdriver`, TLS/JA3 fingerprint, or
similar) and serve a stub page instead of the real site, so the "overhead"
measured is the block page's footprint, not the site's.

**Cause 2 — sustained background traffic (11 of 99 sites), an escalation of
Issue 7.** The same Google IP (`216.239.32.223`) appeared with heavy,
sustained packet counts (773 up to 56,738 packets) in 11 *different* capture
windows spread across the whole ~4 hour batch — meaning some background
process (Drive/Photos/Gmail sync, or similar) was intermittently active for
much of the run, not a one-off blip. Worst case: `zalando.es`'s CDP profile
recorded 0 bytes (page never actually loaded) while its PCAP showed 46 MB,
almost entirely that one Google IP.

**Net effect.** ~15% of site visits (9 + 6, after dedup) had unusable
PCAP/CDP figures, badly skewing mean-based category aggregates even though
the *median* overhead across all 99 sites (304%) was much more plausible and
in line with the clean 10-site pilot.

**Fix.** Added automated, evidence-based outlier flagging to
`run_analysis.py` instead of relying on manual review:
- `MIN_PLAUSIBLE_CDP_BYTES = 5000` — sites with CDP payload below this are
  flagged `likely_bot_blocked_or_failed_load`. Threshold chosen from a clean
  gap in the actual data (9 sites clustered under 2.8 KB, next lowest
  legitimate site was 11.4 KB).
- IQR-based flagging (`Q3 + 3×IQR` of `overhead_pct`, computed only on sites
  that pass the CDP-floor check) marks remaining extreme values as
  `likely_capture_noise`.
- `analyze_run()` now computes category summaries, plots, the dashboard, and
  the top-10 tables from the *clean* subset only; flagged sites are written
  separately to `web_flagged_sites.csv` and listed with their reason in a new
  "Data quality" section of `summary.md`, instead of silently included or
  silently dropped.
- Category tables now lead with **median** overhead/CO₂ (not just mean),
  since a mean computed from only ~10 sites per category is not robust to
  even one or two contaminated visits — full avg/median/min/max is still in
  `web_category_summary.csv`.

Re-running the analysis on `results/20260702_004307` with this fix: category
median overhead dropped to a 121%-678% range (vs. thousands/tens-of-thousands
of percent before), and the top-10 overhead table shows real sites
(`mit`, `cloudflare_blog`, `ecma`, `arstechnica`) with plausible values
instead of block-page artifacts.

**Status:** Mitigated (statistically, at analysis time). Not eliminated at
capture time — bot detection isn't something a headless browser can trivially
avoid, and per-site capture scoping remains out of scope (see Issue 7). If a
clean re-run of the 15 flagged sites is needed for the final memoria numbers,
first close Google Drive/Photos/Gmail and any other sync client to address
Cause 2 (Cause 1 will likely still block some fraction of sites regardless).

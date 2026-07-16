import atexit
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections import defaultdict
from urllib.parse import urlparse

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException


# Known advertising/analytics domains, matched against the resource's
# hostname rather than the full URL
# Extracted from the categories used by Disconnect's Tracking Protection Lists (the basis of Firefox's built-in
# tracking protection) and consistent with the domain-list classification
# approach used in large-scale web-tracking measurement research (Englehardt
# & Narayanan, "Online Tracking: A 1-million-site Measurement and Analysis",
# ACM CCS 2016)

# Kept as a high-confidence subset rather than an exhaustive
# list - precision over recall, so results stay coherent

#### AÑADIR JUSTIFICACIÓN DE DONDE VIENEN ESTOS DOMINIOS Y POR QUÉ SE HAN ELEGIDO (ENGLEHARDT & NARAYANAN, 2016) #### 

TRACKER_DOMAINS = (
    # advertising / ad exchanges
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "adservice.google", "amazon-adsystem.com", "adsrvr.org", "criteo.com",
    "criteo.net", "outbrain.com", "taboola.com", "pubmatic.com",
    "rubiconproject.com", "casalemedia.com", "indexexchange.com",
    "openx.net", "adform.net", "adroll.com", "adnxs.com",
    "smartadserver.com", "media.net", "id5-sync.com", "bat.bing.com",
    "ads-twitter.com", "ads.linkedin.com", "ads.tiktok.com",
    # analytics / behavioral tracking
    "google-analytics.com", "googletagmanager.com", "segment.io",
    "segment.com", "mixpanel.com", "amplitude.com", "hotjar.com",
    "chartbeat.com", "chartbeat.net", "scorecardresearch.com",
    "quantserve.com", "comscore.com", "newrelic.com", "nr-data.net",
    "siteimproveanalytics.io", "brandmetrics.com", "permutive.com",
    "piano.io", "tinypass.com", "analytics.tiktok.com", "analytics.twitter.com",
    "optimizely.com", "adsafeprotected.com", "dotmetrics.net",
    "the-ozone-project.com",
    # social widgets/pixels
    "connect.facebook.net", "platform.twitter.com",
)

# Specific enough as substrings (of the full URL) that they rarely collide
# with unrelated words - unlike a bare "ads", which also matches inside
# "uploads", "downloads" or "readspeaker"


TRACKER_KEYWORDS = (
    "tracking",
    "tracker",
    "telemetry",
    "adsense",
    "pagead",
    "prebid",
    "adservice",
    "adsystem",
    "adsrvr",
)

# Maximum time to wait for a page to load 
### do we have to justify these numbers? 

PAGE_LOAD_TIMEOUT = 45


def _build_chrome_driver(headless: bool = False, fresh_profile: bool = False, keylog_path: str = None) -> webdriver.Chrome:
    # Chrome reads SSLKEYLOGFILE from its own process environment at launch
    # and logs TLS/QUIC session secrets to it in NSS key log format 

    # its the same mechanism as the DoH/DoQ resolvers, so the web pcap can be decrypted in Wireshark too. 
    
    # Set before spawning each Chrome instance so a fresh
    # visit doesn't inherit a stale path from a previous one
    if keylog_path:
        os.environ["SSLKEYLOGFILE"] = keylog_path
    else:
        os.environ.pop("SSLKEYLOGFILE", None)

    options = Options()

    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

    # Suppress Chrome's own background service traffic (account/checkin
    # registration, component/model updates, sync, safe browsing pings...) 

    # the same flag set used by Lighthouse/chrome-launcher to keep web
    # performance measurements from being skewed by browser housekeeping
    # rather than the page itself

    # fresh --user-data-dir looks like a first launch to Chrome, so every visit would otherwise re-trigger this
    # traffic from scratch (confirmed via a decrypted capture showing real requests to 
    # android.clients.google.com, optimizationguide-pa.googleapis.com and accounts.google.com that have nothing to do with the visited site
    options.add_argument("--disable-background-networking")
    options.add_argument("--disable-sync")
    options.add_argument("--disable-component-update")
    options.add_argument("--disable-domain-reliability")
    options.add_argument("--disable-client-side-phishing-detection")
    options.add_argument("--disable-default-apps")
    options.add_argument("--no-first-run")
    options.add_argument("--no-default-browser-check")
    options.add_argument("--disable-search-engine-choice-screen")
    # --disable-component-update above doesn't cover this one: newer Chrome
    # (150.x here) re-downloads its Optimization Guide model on every fresh
    # profile - confirmed via a decrypted capture where a single request to
    # optimizationguide-pa.googleapis.com was 89% of the whole visit's bytes
    options.add_argument(
        "--disable-features=OptimizationHints,OptimizationHintsFetching,"
        "OptimizationTargetPrediction,OptimizationGuideModelDownloading"
    )

    if fresh_profile:
        # Temporary profile directory so each visit starts without cache or
        # service workers from previous sessions 
    
        # important for reproducibility
        tmpdir = tempfile.mkdtemp(prefix="chrome_profile_")
        atexit.register(shutil.rmtree, tmpdir, ignore_errors=True)
        options.add_argument(f"--user-data-dir={tmpdir}")

    # reduce (not eliminate) automation fingerprints that some sites use to
    # serve a bot-challenge page instead of the real content 
    
    # sites relying on TLS/behavioral fingerprinting
    # will still detect a scripted browser regardless of these flags
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    perf_log_prefs = {"enableNetwork": True, "enablePage": False}
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    options.set_capability("goog:perfLoggingPrefs", perf_log_prefs)

    driver = webdriver.Chrome(options=options)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"},
        )
    except WebDriverException:
        pass
    return driver


def _list_descendant_pids(root_pid: int) -> set[int]:
    try:
        result = subprocess.run(
            ["ps", "-ax", "-o", "pid,ppid"], capture_output=True, text=True, timeout=5
        )
    except Exception:
        return {root_pid}

    children_by_parent: dict[int, list[int]] = defaultdict(list)
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        children_by_parent[ppid].append(pid)

    descendants = {root_pid}
    frontier = [root_pid]
    while frontier:
        pid = frontier.pop()
        for child in children_by_parent.get(pid, []):
            if child not in descendants:
                descendants.add(child)
                frontier.append(child)
    return descendants


def _list_local_ports(pids: set[int]) -> set[int]:
    if not pids:
        return set()
    try:
        result = subprocess.run(
            ["lsof", "-i", "-a", "-P", "-n", "-p", ",".join(str(pid) for pid in pids)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return set()

    ports = set()
    for line in result.stdout.splitlines()[1:]:
        match = re.search(r":(\d+)->", line)
        if match:
            ports.add(int(match.group(1)))
    return ports


class _ChromePortWatcher:
    """Polls the Chrome process tree's open sockets so the PCAP can later be
    scoped to only those local ports, instead of every packet on the
    interface (see ISSUES_LOG.md Issue 7: unrelated background traffic was
    contaminating web captures). Best-effort: any failure just means no
    ports are collected and the caller falls back to an unscoped capture.
    """

    def __init__(self, root_pid: int, interval: float = 0.75):
        self._root_pid = root_pid
        self._interval = interval
        self._ports: set[int] = set()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "_ChromePortWatcher":
        self._thread.start()
        return self

    def _run(self):
        while not self._stop_event.is_set():
            try:
                pids = _list_descendant_pids(self._root_pid)
                self._ports.update(_list_local_ports(pids))
            except Exception:
                pass
            self._stop_event.wait(self._interval)

    def stop(self) -> list[int]:
        self._stop_event.set()
        self._thread.join(timeout=2)
        return sorted(self._ports)


def open_website(url: str, duration: int = 10, headless: bool = False, fresh_profile: bool = False, keylog_path: str = None):
    driver = _build_chrome_driver(headless=headless, fresh_profile=fresh_profile, keylog_path=keylog_path)
    try:
        driver.get(url)
        time.sleep(duration)
    except TimeoutException:
        print(f"Timeout loading {url}")
    finally:
        driver.quit()


def _registered_domain(hostname: str) -> str:
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return hostname.lower()
    return ".".join(parts[-2:])


def _classify_resource(page_url: str, resource_url: str) -> str:
    page_host = urlparse(page_url).hostname or ""
    resource_host = (urlparse(resource_url).hostname or "").lower()
    resource_lc = resource_url.lower()

    # Domain check against the hostname only 

    # or a hostname like "readspeaker.com" should never trigger this just
    # because it happens to contain "ads" as a substring
    if any(domain in resource_host for domain in TRACKER_DOMAINS):
        return "tracker_or_ads"
    if any(kw in resource_lc for kw in TRACKER_KEYWORDS):
        return "tracker_or_ads"
    if not resource_host:
        return "unknown_origin"
    if _registered_domain(page_host) == _registered_domain(resource_host):
        return "first_party"
    return "third_party"


def browse_and_profile(
    url: str, duration: int = 10, headless: bool = False, fresh_profile: bool = False, keylog_path: str = None
) -> dict:
    """
    Loads a URL with Selenium + CDP and returns an HTTP traffic profile.

    Returns:
        {
            "url": ...,
            "by_type": {type: bytes, ...},
            "by_origin": {origin_class: bytes, ...},
            "total_bytes": total,
            "network_bytes": total excluding cache/service-worker-served bytes,
            "cached_bytes": bytes served from disk cache or service worker,
            "resources": [{"url", "type", "origin_class", "encodedDataLength", "from_cache"}, ...],
            "chrome_local_ports": local ports used by Chrome's process tree during
                the visit, for scoping the PCAP analysis to this browser's own
                traffic (best-effort; empty if PID/port lookup failed)
        }
    """
    driver = _build_chrome_driver(headless=headless, fresh_profile=fresh_profile, keylog_path=keylog_path)

    port_watcher = None
    try:
        root_pid = driver.service.process.pid
        port_watcher = _ChromePortWatcher(root_pid).start()
    except Exception:
        port_watcher = None

    try:
        try:
            driver.get(url)
        except TimeoutException:
            print(f"Timeout loading {url} -- analyzing traffic captured so far")

        time.sleep(duration)
        logs = driver.get_log("performance")

        meta_by_request = {}
        bytes_by_request = {}

        for entry in logs:
            try:
                message = json.loads(entry["message"])["message"]
            except Exception:
                continue

            method = message.get("method")
            params = message.get("params", {})

            if method == "Network.responseReceived":
                request_id = params.get("requestId")
                response = params.get("response", {})
                resource_type = params.get("type") or response.get("mimeType", "other")
                url_resp = response.get("url", "")

                # only http(s) resources are relevant: chrome://, chrome-extension://,
                # data: and blob: URLs are bundled with the browser or generated
                # in-memory and never cross the network interface

                # If we keep them,
                # CDP totals get inflated with bytes the PCAP can never see (this is
                # what happened with chrome://new-tab-page/* being logged before the
                # actual navigation even starts)

                if not url_resp.startswith(("http://", "https://")):
                    continue

                # CDP exposes whether the resource came from disk cache or a
                # Service Worker instead of the network

                # Those bytes never
                # cross the network interface, so they will never show up in
                # the PCAP
                #
                # they must be excluded from the PCAP vs CDP
                # comparison or the overhead comes out negative
                from_cache = bool(
                    response.get("fromDiskCache") or response.get("fromServiceWorker")
                )
                if request_id:
                    meta_by_request[request_id] = {
                        "type": resource_type,
                        "url": url_resp,
                        "from_cache": from_cache,
                    }

            elif method == "Network.loadingFinished":
                request_id = params.get("requestId")
                encoded_len = params.get("encodedDataLength", 0)
                if request_id:
                    bytes_by_request[request_id] = bytes_by_request.get(request_id, 0) + encoded_len

        by_type = defaultdict(int)
        by_origin = defaultdict(int)
        resources = []
        total_bytes = 0
        network_bytes = 0
        cached_bytes = 0

        for request_id, size in bytes_by_request.items():
            meta = meta_by_request.get(request_id)
            if meta is None:
                # No matching http(s) responseReceived event was kept for this
                # request (filtered out above, or a type of event we don't
                # track)
                # skip it instead of silently putting it as
                # "unknown_origin", which would reintroduce the same
                # non-network bytes we just filtered out
                
                continue

            rtype = meta.get("type", "unknown")
            url_resp = meta.get("url", "")
            from_cache = meta.get("from_cache", False)
            origin_class = _classify_resource(url, url_resp)
            by_type[rtype] += size
            by_origin[origin_class] += size
            total_bytes += size
            if from_cache:
                cached_bytes += size
            else:
                network_bytes += size
            resources.append({
                "requestId": request_id,
                "type": rtype,
                "origin_class": origin_class,
                "url": url_resp,
                "encodedDataLength": size,
                "from_cache": from_cache,
            })

        chrome_ports = port_watcher.stop() if port_watcher else []

        return {
            "url": url,
            "by_type": dict(by_type),
            "by_origin": dict(by_origin),
            "total_bytes": total_bytes,
            "network_bytes": network_bytes,
            "cached_bytes": cached_bytes,
            "resources": resources,
            "chrome_local_ports": chrome_ports,
        }

    finally:
        if port_watcher:
            port_watcher.stop()
        driver.quit()
import atexit
import json
import shutil
import tempfile
import time
from collections import defaultdict
from urllib.parse import urlparse

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException


TRACKER_KEYWORDS = (
    "analytics",
    "doubleclick",
    "googletagmanager",
    "google-analytics",
    "facebook",
    "pixel",
    "ads",
    "adservice",
    "tracking",
    "tracker",
    "telemetry",
    "metrics",
)

# Maximum time to wait for a page to load
PAGE_LOAD_TIMEOUT = 45


def _build_chrome_driver(headless: bool = False, fresh_profile: bool = False) -> webdriver.Chrome:
    options = Options()

    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

    if fresh_profile:
        # Temporary profile directory so each visit starts without cache or
        # service workers from previous sessions - important for reproducibility
        tmpdir = tempfile.mkdtemp(prefix="chrome_profile_")
        atexit.register(shutil.rmtree, tmpdir, ignore_errors=True)
        options.add_argument(f"--user-data-dir={tmpdir}")

    perf_log_prefs = {"enableNetwork": True, "enablePage": False}
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    options.set_capability("goog:perfLoggingPrefs", perf_log_prefs)

    driver = webdriver.Chrome(options=options)
    driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return driver


def open_website(url: str, duration: int = 10, headless: bool = False, fresh_profile: bool = False):
    driver = _build_chrome_driver(headless=headless, fresh_profile=fresh_profile)
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
    resource_host = urlparse(resource_url).hostname or ""
    resource_lc = resource_url.lower()

    if any(kw in resource_lc for kw in TRACKER_KEYWORDS):
        return "tracker_or_ads"
    if not resource_host:
        return "unknown_origin"
    if _registered_domain(page_host) == _registered_domain(resource_host):
        return "first_party"
    return "third_party"


def browse_and_profile(url: str, duration: int = 10, headless: bool = False, fresh_profile: bool = False) -> dict:
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
            "resources": [{"url", "type", "origin_class", "encodedDataLength", "from_cache"}, ...]
        }
    """
    driver = _build_chrome_driver(headless=headless, fresh_profile=fresh_profile)
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

                # Only http(s) resources are relevant: chrome://, chrome-extension://,
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
                # the PCAP - they must be excluded from the PCAP vs CDP
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
                # track) - skip it instead of silently bucketing it as
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

        return {
            "url": url,
            "by_type": dict(by_type),
            "by_origin": dict(by_origin),
            "total_bytes": total_bytes,
            "network_bytes": network_bytes,
            "cached_bytes": cached_bytes,
            "resources": resources,
        }

    finally:
        driver.quit()
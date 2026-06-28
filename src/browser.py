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

# Tiempo máximo de espera para que cargue una página
PAGE_LOAD_TIMEOUT = 45


def _build_chrome_driver(headless: bool = False, fresh_profile: bool = False) -> webdriver.Chrome:
    options = Options()

    if headless:
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

    if fresh_profile:
        # directorio temporal de perfil para que cada visita empiece sin caché ni
        # service workers de sesiones anteriores — importante para reproducibilidad
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
        print(f"Timeout cargando {url}")
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
    Carga una URL con Selenium + CDP y devuelve un perfil de tráfico HTTP.

    Retorna:
        {
            "url": ...,
            "by_type": {tipo: bytes, ...},
            "by_origin": {clase_origen: bytes, ...},
            "total_bytes": total,
            "resources": [{"url", "type", "origin_class", "encodedDataLength"}, ...]
        }
    """
    driver = _build_chrome_driver(headless=headless, fresh_profile=fresh_profile)
    try:
        try:
            driver.get(url)
        except TimeoutException:
            print(f"Timeout cargando {url} — se analizará el tráfico capturado hasta ahora")

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
                if request_id:
                    meta_by_request[request_id] = {"type": resource_type, "url": url_resp}

            elif method == "Network.loadingFinished":
                request_id = params.get("requestId")
                encoded_len = params.get("encodedDataLength", 0)
                if request_id:
                    bytes_by_request[request_id] = bytes_by_request.get(request_id, 0) + encoded_len

        by_type = defaultdict(int)
        by_origin = defaultdict(int)
        resources = []
        total_bytes = 0

        for request_id, size in bytes_by_request.items():
            meta = meta_by_request.get(request_id, {"type": "unknown", "url": ""})
            rtype = meta.get("type", "unknown")
            url_resp = meta.get("url", "")
            origin_class = _classify_resource(url, url_resp)
            by_type[rtype] += size
            by_origin[origin_class] += size
            total_bytes += size
            resources.append({
                "requestId": request_id,
                "type": rtype,
                "origin_class": origin_class,
                "url": url_resp,
                "encodedDataLength": size,
            })

        return {
            "url": url,
            "by_type": dict(by_type),
            "by_origin": dict(by_origin),
            "total_bytes": total_bytes,
            "resources": resources,
        }

    finally:
        driver.quit()

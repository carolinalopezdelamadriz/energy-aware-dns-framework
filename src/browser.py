from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import json
from collections import defaultdict


def _build_chrome_driver_with_cdp() -> webdriver.Chrome:
    
    options = Options()
    # activar el modo headless 
    # options.add_argument("--headless=new")

    perf_log_prefs = {
        "enableNetwork": True,
        "enablePage": False,
    }
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    options.set_capability("goog:perfLoggingPrefs", perf_log_prefs)

    driver = webdriver.Chrome(options=options)
    
    return driver


def open_website(url, duration: int = 10):
    #Abre una web simplemente, esperando `duration` segundos para que cargue y se capture tráfico en la red
    
    driver = webdriver.Chrome()
    try:
        driver.get(url)
        time.sleep(duration)
    finally:
        driver.quit()


def browse_and_profile(url: str, duration: int = 10):
    #Abre una web usando Selenium + CDP y devuelve un perfil de tráfico HTTP.

    #  Extrae de los logs de rendimiento de Chrome los eventos
    # `Network.responseReceived` y `Network.loadingFinished`, calculando el
    # tamaño transferido por tipo de recurso (document, script, image, etc.).

    """Devuelve un diccionario:
        {
            "by_type": {resourceType: bytes, ...},
            "total_bytes": total,
            "resources": [
                {"url": ..., "type": ..., "encodedDataLength": ...},
                ...
            ],
        }
    """
    driver = _build_chrome_driver_with_cdp()
    try:
        driver.get(url)
        time.sleep(duration)

        logs = driver.get_log("performance")

        # requestId -> (resourceType, url)
        meta_by_request = {}
        bytes_by_request = {}

        for entry in logs:
            try:
                message = json.loads(entry["message"])["message"]
            except Exception:
                continue

            method = message.get("method")
            params = message.get("params", {})

            # Network.responseReceived: metadata del recurso
            if method == "Network.responseReceived":
                request_id = params.get("requestId")
                response = params.get("response", {})
                resource_type = params.get("type") or response.get("mimeType", "other")
                url_resp = response.get("url", "")
                if request_id:
                    meta_by_request[request_id] = {
                        "type": resource_type,
                        "url": url_resp,
                    }

            # Network.loadingFinished: tamaño descargado
            elif method == "Network.loadingFinished":
                request_id = params.get("requestId")
                encoded_len = params.get("encodedDataLength", 0)
                if request_id:
                    bytes_by_request[request_id] = bytes_by_request.get(
                        request_id, 0
                    ) + encoded_len

        by_type = defaultdict(int)
        resources = []
        total_bytes = 0

        for request_id, size in bytes_by_request.items():
            meta = meta_by_request.get(
                request_id, {"type": "unknown", "url": ""}
            )
            rtype = meta.get("type", "unknown")
            url_resp = meta.get("url", "")
            by_type[rtype] += size
            total_bytes += size
            resources.append(
                {
                    "requestId": request_id,
                    "type": rtype,
                    "url": url_resp,
                    "encodedDataLength": size,
                }
            )

        profile = {
            "by_type": dict(by_type),
            "total_bytes": total_bytes,
            "resources": resources,
        }

        return profile
    finally:
        driver.quit()

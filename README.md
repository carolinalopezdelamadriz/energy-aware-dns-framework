# Energy-Aware DNS Framework

Este repositorio contiene el framework que estoy desarrollando para mi TFG. La idea principal es medir cuánto tráfico generan distintos protocolos de resolución DNS y cómo se puede traducir ese tráfico a una estimación de energía y CO2.

Título del TFG: **Framework-Based Energy-Aware Analysis of encrypted DNS: The Carbon Cost of Privacy**

## Qué mide

El framework trabaja en dos niveles:

- resolución DNS aislada, comparando DNS clásico, DNS over HTTPS (DoH) y DNS over QUIC (DoQ);
- navegación web real, capturando tanto el tráfico de red como los recursos que ve el navegador.

La comparación importante es esta:

- CDP muestra los recursos que Chrome carga: HTML, scripts, imágenes, fuentes, etc.;
- PCAP muestra lo que realmente pasa por la red: DNS, TLS, QUIC, cabeceras, ACKs, handshakes y tráfico auxiliar.

Con esos bytes, el framework calcula una estimación sencilla de energía y CO2. No pretende dar un valor absoluto universal, sino usar el mismo modelo para comparar escenarios de forma consistente.

## Requisitos

- Python 3.9+
- Google Chrome y ChromeDriver compatible con Selenium
- `tcpdump`
- `kdig` con soporte QUIC para las pruebas de DoQ
- dependencias de Python incluidas en `requirements.txt`

```bash
pip install -r requirements.txt
```

DoQ necesita `aioquic`. Antes de lanzar experimentos conviene comprobar el entorno:

```bash
python3 src/main.py --mode check --interface en0
```

Para comprobar si DoQ funciona desde la red actual:

```bash
python3 src/main.py --mode check --interface en0 --check-doq --doq-resolver quad9
```

En macOS, `tcpdump` suele necesitar permisos de administrador.

## Uso básico

Ejecutar el flujo completo:

```bash
python src/main.py
```

Ejecutar solo la comparación DNS:

```bash
python src/main.py --mode dns --domain bbc.com --repetitions 5
```

En macOS normalmente hay que indicar la interfaz de red. Para Wi-Fi suele ser `en0`:

```bash
python src/main.py --mode dns --protocols dns doh --domain bbc.com --repetitions 5 --interface en0
```

Si `tcpdump` da error de permisos:

```bash
sudo -E python src/main.py --mode dns --protocols dns doh --domain bbc.com --repetitions 5 --interface en0
```

Ejecutar solo la parte de navegación web:

```bash
python src/main.py --mode web --url https://www.bbc.com
```

Seleccionar protocolos concretos:

```bash
python src/main.py --mode dns --protocols dns doh
```

## Estructura

```text
energy-aware-dns-framework/
├── src/                         # código del framework
├── data/
│   └── sites_sample.csv         # muestra pequeña de prueba
├── results/
│   ├── run_20260626/            # ejecución piloto que dejo como referencia
│   └── archive/                 # ejecuciones locales que no quiero subir
├── README.md
└── requirements.txt
```

Las ejecuciones nuevas crean carpetas con timestamp dentro de `results/`. Los PCAP se ignoran porque pueden ser grandes y además son capturas brutas de red. En cambio, la ejecución piloto conserva CSV, JSON y figuras para que se pueda revisar el pipeline sin tener que relanzar todo.

## Ejecución por lotes

La carpeta `results/run_20260626/` contiene una primera ejecución pequeña con cinco webs. La uso como validación inicial del framework, no como resultado final del TFG.

Primero comprobaría el entorno:

```bash
python3 src/main.py --mode check --interface en0
```

Después se puede lanzar el batch:

```bash
sudo -E python3 src/main.py \
  --mode batch \
  --sites-file data/sites_sample.csv \
  --protocols dns doh doq \
  --repetitions 5 \
  --web-repetitions 1 \
  --interface en0 \
  --doq-resolver quad9
```

Esto genera una carpeta nueva dentro de `results/`, por ejemplo:

```text
results/20260626_103000/
  manifest.json
  dns_results.csv
  web_results.csv
  web_profile_<timestamp>.json
  dns_<protocol>_<timestamp>.pcap
  web_<timestamp>.pcap
```

Después se genera el análisis:

```bash
python3 src/main.py --mode analyze --run-dir results/20260626_103000
```

El análisis crea:

```text
results/<run_id>/analysis/
  summary.md
  dns_protocol_summary.csv
  web_category_summary.csv
  web_origin_summary.csv
  web_origin_resources.csv
  fig_dns_avg_bytes.png
  fig_web_traffic_comparison.png
  fig_web_origin_bytes.png
  fig_dashboard.png
```

Para regenerar las figuras de la ejecución piloto:

```bash
python3 src/main.py --mode analyze --run-dir results/run_20260626
```

Ese análisis compara bytes por protocolo, estima CFP, cruza el payload visto por CDP con el tráfico capturado en PCAP y saca un primer desglose de recursos por origen.

También se puede usar `--skip-web` para probar solo DNS, o `--skip-dns` para probar solo Selenium/CDP.

Una cosa importante con DoQ: depende de que la red permita UDP/853 y de que el resolver responda bien. Por eso el framework usa un único resolver DoQ por ejecución, `quad9` por defecto. Si se prueban varios resolvers dentro de la misma captura, el PCAP se ensucia con handshakes fallidos y retransmisiones, y luego los bytes ya no son comparables.

## Modelo de carbono

El modelo actual es simple a propósito y está pensado para poder cambiar las constantes cuando cierre la parte bibliográfica:

```text
E[J] = bytes * energy_per_byte_j
E[kWh] = E[J] / 3.6e6
CO2[kgCO2e] = E[kWh] * co2_per_kwh
```

## Autoría

Carolina López De La Madriz | Double Degree in Data Science and Engineering and Telecommunication Technologies Engineering

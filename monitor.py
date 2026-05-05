"""
monitor.py — Monitorizare live trafic IoT cu detecție anomalii ECOD

Flux per dispozitiv la fiecare WINDOW_SECONDS secunde:
    1. tcpdump rulează în containerul dispozitivului
    2. PCAP-ul e copiat pe host cu docker cp
    3. Extractorul C procesează PCAP → CSV
    4. inference.py calculează scoruri ECOD
    5. Rezultatele sunt afișate în terminal
"""

import subprocess
import threading
import time
import os
import sys
from datetime import datetime
from inference import incarca_modele, proceseaza_csv
import signal
from inference import incarca_modele, proceseaza_csv
from response import init_response, proceseaza_raspuns
from ai_agent import analiza_ai

# Durata unei ferestre de captură în secunde
WINDOW_SECONDS = 10
EXTRACTOR_BIN = 'extractor/build/extractor'
TMP_DIR = '/tmp/iot_monitor'
MODEL_DIR = 'models'
DISPOZITIVE = {
    'gateway'      : {'container': 'gateway',      'ip': '172.20.0.2'},
    'iot_sensor'   : {'container': 'iot_sensor',   'ip': '172.20.0.4'},
    'auth_server'  : {'container': 'auth_server',  'ip': '172.20.0.5'},
    'web_server'   : {'container': 'web_server',   'ip': '172.20.0.3'},
    'smart_camera' : {'container': 'smart_camera', 'ip': '172.20.0.6'},
    'smart_plug'   : {'container': 'smart_plug',   'ip': '172.20.0.7'},
}

CULORI = {
    'INFO' : '\033[0m',    # normal
    'OK'   : '\033[92m',   # verde
    'WARN' : '\033[93m',   # galben
    'ALARM': '\033[91m',   # rosu
    'RESET': '\033[0m',
}

def log(device, mesaj, nivel='INFO'):
    ts = datetime.now().strftime('%H:%M:%S')
    culoare = CULORI.get(nivel, CULORI['INFO'])
    reset = CULORI['RESET']
    print(f"{culoare}[{ts}] [{device:12s}] {mesaj}{reset}", flush=True)


def captureaza_pcap(device, container, ip, fereastra_id):
    """
    Rulează tcpdump în containerul dispozitivului exact ca la antrenare:
        docker exec <container> tcpdump -ni any host <IP> -w /pcap/x.pcap

    Returnează calea PCAP-ului pe host, sau None dacă eșuează.
    """
    pcap_in_container = f'/tmp/{device}_{fereastra_id}.pcap'
    pcap_pe_host = os.path.join(TMP_DIR, f'{device}_{fereastra_id}.pcap')
    cmd = [
        'docker', 'exec', container,
        'timeout', '-s', 'INT', str(WINDOW_SECONDS),
        'tcpdump', '-ni', 'eth0',
        '-s', '96',   # ADAUGAT: snapshot 96 bytes — reduce PCAP de la 100MB la ~2MB
        '-U',
        'host', ip,
        '-w', pcap_in_container,
    ]

    log(device, f"Captura start (fereastra {fereastra_id})...")

    # try:
    #     subprocess.run(
    #         cmd,
    #         stdout=subprocess.DEVNULL,
    #         stderr=subprocess.DEVNULL,
    #         timeout=WINDOW_SECONDS + 5
    #     )
    # except subprocess.TimeoutExpired:
    #     log(device, "tcpdump timeout", 'WARN')
    #     return None
    # except Exception as e:
    #     log(device, f"Eroare tcpdump: {e}", 'WARN')
    #     return None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(WINDOW_SECONDS)

        # Oprim tcpdump din interiorul containerului cu SIGINT
        # proc.terminate() oprește doar docker exec, nu tcpdump din container
        subprocess.run(
            ['docker', 'exec', container, 'pkill', '-INT', 'tcpdump'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    except Exception as e:
        log(device, f"Eroare tcpdump: {e}")
        return None

    cmd_cp = [
        'docker', 'cp',
        f'{container}:{pcap_in_container}',
        pcap_pe_host,
    ]

    try:
        subprocess.run(
            cmd_cp,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        log(device, f"Eroare docker cp: {e}", 'WARN')
        return None

    if not os.path.exists(pcap_pe_host):
        log(device, "PCAP lipsă după docker cp", 'WARN')
        return None

    size = os.path.getsize(pcap_pe_host)
    if size < 100:
        os.remove(pcap_pe_host)
        return None

    log(device, f"PCAP ok ({size:,} bytes)")
    return pcap_pe_host


def extrage_csv(device, pcap_path, fereastra_id):
    csv_path = os.path.join(TMP_DIR, f'{device}_{fereastra_id}.csv')

    cmd = [
        EXTRACTOR_BIN,
        pcap_path,
        device,
        csv_path,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            log(device, f"Eroare extractor: {result.stderr.strip()}", 'WARN')
            return None

    except subprocess.TimeoutExpired:
        log(device, "Extractor timeout", 'WARN')
        return None
    except Exception as e:
        log(device, f"Eroare extractor: {e}", 'WARN')
        return None

    if not os.path.exists(csv_path):
        log(device, "CSV lipsă după extractor", 'WARN')
        return None

    return csv_path


def analizeaza(device, csv_path, modele):
    rezultate = proceseaza_csv(csv_path, device, modele)

    if not rezultate:
        log(device, "Niciun flux în această fereastra")
        return []

    anomalii = [r for r in rezultate if r['anomalie']]
    normale  = [r for r in rezultate if not r['anomalie']]

    nivel = 'ALARM' if anomalii else 'OK'
    log(device,
        f"{len(rezultate)} fluxuri | "
        f"{len(normale)} normale | "
        f"{len(anomalii)} anomalii",
        nivel)

    for r in anomalii:
        top = r['top_features'][0] if r['top_features'] else {}
        log(device,
            f"ANOMALIE | "
            f"{r['src_ip']}:{r['src_port']} → "
            f"{r['dst_ip']}:{r['dst_port']} | "
            f"scor={r['scor']:.2f} vs threshold={r['threshold']:.2f} | "
            f"feature: {top.get('feature','?')} "
            f"val={top.get('valoare','?')} "
            f"z={top.get('zscore', '?'):+}σ",
            'ALARM')
    #proceseaza_raspuns(rezultate)
    proceseaza_raspuns(rezultate, ai_callback=analiza_ai)

    return rezultate

def curata(device, fereastra_id):
    for ext in ['pcap', 'csv']:
        path = os.path.join(TMP_DIR, f'{device}_{fereastra_id}.{ext}')
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────
# BUCLA PRINCIPALA PER DISPOZITIV
# Rulam în thread separat — toate dispozitivele în paralel
# ─────────────────────────────────────────────────────────────────

def bucla_dispozitiv(device, config, modele):
    container = config['container']
    ip = config['ip']

    log(device, f"Pornit | container={container} | ip={ip} | fereastră={WINDOW_SECONDS}s")

    fereastra_id = 0

    while True:
        fereastra_id += 1

        pcap = captureaza_pcap(device, container, ip, fereastra_id)
        if pcap is None:
            time.sleep(1)
            continue

        csv = extrage_csv(device, pcap, fereastra_id)
        if csv is None:
            curata(device, fereastra_id)
            continue

        analizeaza(device, csv, modele)
        curata(device, fereastra_id)


def main():
    print()
    print("=" * 60)
    print("  IoT IDPS — Anomaly Detection Monitor")
    print(f"  Fereastră: {WINDOW_SECONDS}s | Dispozitive: {len(DISPOZITIVE)}")
    print("=" * 60)
    print()

    if not os.path.exists(EXTRACTOR_BIN):
        print(f"EROARE: Extractor C nu găsit: {EXTRACTOR_BIN}")
        sys.exit(1)

    if not os.path.exists(os.path.join(MODEL_DIR, 'registry.json')):
        print(f"EROARE: Modele lipsă în {MODEL_DIR}/")
        print("Rulează mai întâi ecod_manual.ipynb")
        sys.exit(1)

    os.makedirs(TMP_DIR, exist_ok=True)
    print("Încarc modelele ECOD...\n")
    modele = incarca_modele(MODEL_DIR)
    print()

    init_response()

    # Verificare daca containerele ruleaza
    print("Verific containerele Docker...")
    for device, config in DISPOZITIVE.items():
        try:
            subprocess.run(
                ['docker', 'exec', config['container'], 'echo', 'ok'],
                check=True, capture_output=True, timeout=5
            )
            print(f"{config['container']}")
        except Exception:
            print(f"{config['container']} — container oprit sau lipsă")

    print()
    print("Pornesc monitorizarea în paralel...")
    print("-" * 60)
    print()

    threads = []
    for device, config in DISPOZITIVE.items():
        if device not in modele:
            print(f"Sarim {device} — model lipsă")
            continue

        t = threading.Thread(
            target=bucla_dispozitiv,
            args=(device, config, modele),
            daemon=True,
            name=f"monitor-{device}",
        )
        t.start()
        threads.append(t)
        time.sleep(0.5)  
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nOprire monitor.")


if __name__ == '__main__':
    main()
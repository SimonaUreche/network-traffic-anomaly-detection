# clasifica severitatea pe baza scorului ECOD
# aplica iptables (DROP sau rate-limit) în containerul victimă
# tine evidenta blocarii actrive
# thread de deblocare automată după expirare timer
import subprocess
import threading
import time
import os
import json
from datetime import datetime
from database import (
    init_db, salveaza_incident as db_salveaza_incident,
    actualizeaza_incident as db_actualizeaza_incident,
    salveaza_istoric_blocare, get_istoric_blocare,
    salveaza_anomalie,
)

INTERNAL_SUBNET = DISPOZITIVE_IOT = {
    '172.20.0.2',   # gateway
    '172.20.0.3',   # web_server
    '172.20.0.4',   # iot_sensor
    '172.20.0.5',   # auth_server
    '172.20.0.6',   # smart_camera
    '172.20.0.7',   # smart_plug — poate fi compromis (Mirai)
    '172.20.0.53',  # dns_server
}

# Timer-e DEFAULT de deblocare (secunde) — AI-ul le poate ajusta
TIMER_LOW_MEDIUM = 180    # 3 minute — pentru LOW/MEDIUM
TIMER_HIGH = 300          # 5 minute — pentru HIGH (AI ajustează)
TIMER_MAX = 86400         # 24 ore — cap maxim la dublare
TIMER_VERIFICARE = 30     # La fiecare 30 sec verificăm dacă expiră

# Praguri escaladare
ANOMALII_PERSISTENTE = 5  # 5+ anomalii de la același IP în 5 min → HIGH

# Folder pentru incidente
INCIDENTS_DIR = 'incidents'
INCIDENTS_PCAP_DIR = os.path.join(INCIDENTS_DIR, 'pcaps')

# Mapare dispozitiv → container Docker
DISPOZITIV_CONTAINER = {
    'gateway':      'gateway',
    'iot_sensor':   'iot_sensor',
    'auth_server':  'auth_server',
    'web_server':   'web_server',
    'smart_camera': 'smart_camera',
    'smart_plug':   'smart_plug'
}

# Gateway IP — permis pentru smart_plug izolat (MQTT normal)
GATEWAY_IP = '172.20.0.2'
MQTT_PORT = 1883

# Dictionar cu toate blocarile active in acest moment (cheia IP-ul atacatorului si valoarea e alt dictionar cu detaliile blocarii)
# Fololsit de timer pentru deblocare si de proceseaza_raspuns pentru a stii daca IP-ul e deja blocat 
blocari_active = {}
# Dictionar pentru dispozitive izolate (doar pentru atacuri interne) — cheia e containerul izolat, valoarea e detaliile izolarii (timestamp, timer, IP atacator)
izolari_active = {} #separat de blocari_active pt ca izolarea se face pe output(pe atacatorul intern), nu pe input (pe victima), și are reguli diferite de iptables

#Lista cu toate anomaliile din ultimele 5 minute (tuplu: timestamp, ip_sursa, device, scor) — folosit de calculeaza_severitate pentru a calcula 
#pattern-uri persistente (daca acelasi IP genereaza mult de 5+ anomalii in 5 minute e atac)
istoric_anomalii = []

# Istoric blocări anterioare: { ip: ultimul_timer_secunde }
# Folosit pentru dublarea timer-ului la revenire
istoric_blocari = {}

# IP-uri pe care adminul le-a marcat ca "IGNORE" (trusted) pentru o perioada limitata, stocate cu timestamp de expirare - pt 30 min este ignorat daca mai apar alerte
trusted_list = {}

# Lock pentru thread safety - monitor.py ruleaza thred-uri diferite/dispozitiv, iar thread-ul de verificare timer ruleaza in paralel
_lock = threading.Lock()

# Contor incidente
_incident_counter = 0

def _genereaza_incident_id(): #id unic per incident, format: INC-YYYY-MM-DD-XXXX (XXXX = numar incremental) folosit ca nume de fisier si ca referinta in dashboard
    """Generează un ID unic pentru fiecare incident."""
    global _incident_counter
    _incident_counter += 1
    data = datetime.now().strftime('%Y-%m-%d')
    return f"INC-{data}-{_incident_counter:04d}"

def _este_ip_intern(ip):
    """Verifică dacă IP-ul e un dispozitiv IoT cunoscut din rețea."""
    return ip in DISPOZITIVE_IOT

# Verificare trusted list - dacă adminul a marcat un IP ca "IGNORE" pentru o perioadă, nu aplicăm blocări pentru acel IP
def _este_trusted(ip):
    """Verifică dacă IP-ul e pe trusted list temporar (marcat IGNORE de admin)."""
    with _lock:
        if ip in trusted_list:
            if time.time() < trusted_list[ip]:
                return True
            else:
                del trusted_list[ip]
        return False

# apelata din dashboard cand adminul apasa IGNORE - adauga iP in in trusted pt 30 min
def adauga_trusted(ip, durata_secunde=1800):
    """Adaugă un IP pe trusted list pentru o durată (default 30 min)."""
    with _lock:
        trusted_list[ip] = time.time() + durata_secunde
    _log_response('system', f"IP {ip} adăugat pe trusted list ({durata_secunde}s)", 'UNBLOCK')

#adaga o anomalie in istoric si curatam intrarile mai vechi de 5 minute 
def _adauga_in_istoric(ip_sursa, device, scor):
    with _lock:
        acum = time.time()
        istoric_anomalii.append((acum, ip_sursa, device, scor))
        # Curățăm intrări mai vechi de 5 minute
        limita = acum - 300
        while istoric_anomalii and istoric_anomalii[0][0] < limita:
            istoric_anomalii.pop(0)

# Numărăm câte anomalii au fost de la acelasi IP în ultimele 5 minute (pentru clasificare severitate)
def _numar_anomalii_recente(ip_sursa, minute=5):
    with _lock:
        limita = time.time() - (minute * 60)
        return sum(1 for ts, ip, _, _ in istoric_anomalii
                   if ip == ip_sursa and ts >= limita)

#rosu pentru BLOCK
#galben pentru RATE
#verde pentru UNBLOCK
#magenta pentru mesaje HUMAN (ex: admin a marcat IGNORE)
#cyan pentru mesaje AI (decizii automate)
def _log_response(device, mesaj, nivel='INFO'):
    ts = datetime.now().strftime('%H:%M:%S')
    culori = {
        'INFO':    '\033[0m',
        'BLOCK':   '\033[91m',     # roșu
        'RATE':    '\033[93m',     # galben
        'UNBLOCK': '\033[92m',     # verde
        'HUMAN':   '\033[95m',     # magenta
        'AI':      '\033[96m',     # cyan
    }
    culoare = culori.get(nivel, '\033[0m')
    print(f"{culoare}[{ts}] [RESPONSE] [{device:12s}] {mesaj}\033[0m", flush=True)



def calculeaza_severitate(anomalie, context):
    """
    Clasifică severitatea pe baza regulilor locale. Instant (<1ms).
 
    Ratio = scor / threshold:
      - ratio < 1.5      → LOW
      - 1.5 ≤ ratio < 3  → MEDIUM
      - ratio ≥ 3        → HIGH
 
    Override:
      - 5+ anomalii de la același IP în 5 min → HIGH
    """
    ratio = anomalie['scor'] / anomalie['threshold']
 
    if context['anomalii_5min'] >= ANOMALII_PERSISTENTE:
        return 'HIGH'
 
    if ratio >= 3:
        return 'HIGH'
    elif ratio >= 1.5:
        return 'MEDIUM'
    else:
        return 'LOW'


# ACȚIUNI IPTABLES

def _exec_iptables(container, regula):
    """Execută o comandă iptables în containerul Docker."""
    cmd = f"docker exec {container} iptables {regula}"
    try:
        subprocess.run(
            cmd.split(),
            capture_output=True,
            timeout=5,
        )
        return True
    except Exception as e:
        _log_response(container, f"Eroare iptables: {e}")
        return False


def aplica_drop(container, ip_atacator):
    """
    Blocare completă — DROP toate pachetele de la IP-ul atacator.
    Folosit pentru severitate HIGH.
    """
    # Verificăm să nu adăugăm regula de două ori
    check = f"-C INPUT -s {ip_atacator} -j DROP"
    result = subprocess.run(
        f"docker exec {container} iptables {check}".split(),
        capture_output=True,
    )
    if result.returncode == 0:
        return True  # Regula există deja

    regula = f"-A INPUT -s {ip_atacator} -j DROP"
    succes = _exec_iptables(container, regula)
    if succes:
        _log_response(container, f"DROP aplicat: {ip_atacator}", 'BLOCK')
    return succes

# LOW permite 5 conexiuli in 60s
# MEDIUM permite 2 conexiuni in 10s
# chain separat pentru fiecare IP atacator, pentru a fi sterse separat si a nu afecta alte iptables
def aplica_rate_limit(container, ip_atacator, port, hits_per_interval=5, interval_sec=60):
    """
    Rate limiting — permite trafic normal, blochează excesul.
    Folosit pentru severitate LOW/MEDIUM.

    Args:
        hits_per_interval: câte conexiuni noi sunt permise
        interval_sec: în câte secunde
    """
    chain_name = f"RL_{ip_atacator.replace('.', '_')}"

    comenzi = [
        f"-N {chain_name}",
        f"-A {chain_name} -m recent --set --name {chain_name}",
        f"-A {chain_name} -m recent --update --seconds {interval_sec} "
        f"--hitcount {hits_per_interval} --name {chain_name} -j DROP",
        f"-A {chain_name} -j ACCEPT",
        f"-A INPUT -s {ip_atacator} -p tcp --dport {port} "
        f"-m state --state NEW -j {chain_name}",
    ]

    for cmd in comenzi:
        _exec_iptables(container, cmd)

    _log_response(container,
                  f"Rate-limit aplicat: {ip_atacator} → "
                  f"max {hits_per_interval} conn/{interval_sec}s pe port {port}",
                  'RATE')
    return True


def scoate_drop(container, ip_atacator):
    """Scoate regula DROP pentru un IP."""
    regula = f"-D INPUT -s {ip_atacator} -j DROP"
    succes = _exec_iptables(container, regula)
    if succes:
        _log_response(container, f"DROP scos: {ip_atacator}", 'UNBLOCK')
    return succes


def scoate_rate_limit(container, ip_atacator, port):
    """Scoate regulile de rate limit pentru un IP."""
    chain_name = f"RL_{ip_atacator.replace('.', '_')}"

    comenzi = [
        f"-D INPUT -s {ip_atacator} -p tcp --dport {port} "
        f"-m state --state NEW -j {chain_name}",
        f"-F {chain_name}",
        f"-X {chain_name}",
    ]

    for cmd in comenzi:
        _exec_iptables(container, cmd)

    _log_response(container, f"Rate-limit scos: {ip_atacator}", 'UNBLOCK')
    return True

#####
#Pt atacurile interne - izolam complet dispozitivul compromis (ex: smart_plug) — blocam tot traficul de iesire, cu exceptia MQTT catre gateway (pentru a nu afecta functionarea normala a smart_plug, dar sa nu poata ataca alte dispozitive din retea)
def izoleaza_dispozitiv(container):
    """
    Izolează un dispozitiv compromis — permite doar MQTT la gateway.
    Folosit pentru atacuri interne (smart_plug compromis).
    """
    comenzi = [
        f"-A OUTPUT -d {GATEWAY_IP} -p tcp --dport {MQTT_PORT} -j ACCEPT",
        f"-A OUTPUT -p udp --dport 53 -j ACCEPT",
        f"-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        f"-A OUTPUT -j DROP",
    ]

    for cmd in comenzi:
        _exec_iptables(container, cmd)

    _log_response(container, f"Dispozitiv IZOLAT — doar MQTT permis", 'BLOCK')
    return True


def deizoleaza_dispozitiv(container):
    """Scoate izolarea — resetează regulile OUTPUT."""
    _exec_iptables(container, "-F OUTPUT")
    _log_response(container, f"Izolare SCOASĂ", 'UNBLOCK')
    return True


# GESTIONARE BLOCĂRI ACTIVE + TIMER-E
def _calculeaza_timer(severitate, ip_atacator):
    """
    Calculează timer-ul inițial, cu dublare dacă IP-ul a mai fost blocat.
 
    Prima blocare:  timer default (3 min sau 5 min)
    A doua blocare: timer anterior × 2
    A treia:        timer anterior × 2 (din nou)
    Cap maxim:      24 ore
    """
    # Timer default pe baza severității
    if severitate == 'HIGH':
        timer_default = TIMER_HIGH
    else:
        timer_default = TIMER_LOW_MEDIUM
 
    # Verificăm dacă IP-ul a mai fost blocat anterior
    with _lock:
        if ip_atacator in istoric_blocari:
            timer_anterior = istoric_blocari[ip_atacator]
            timer_nou = min(timer_anterior * 2, TIMER_MAX)
            _log_response('system',
                          f"IP {ip_atacator} revenit — timer dublat: "
                          f"{timer_anterior}s → {timer_nou}s",
                          'BLOCK')
            return timer_nou
 
    # Verificăm în SQLite (persistent la restart)
    istoric = get_istoric_blocare(ip_atacator)
    if istoric:
        timer_anterior = istoric['ultimul_timer']
        timer_nou = min(timer_anterior * 2, TIMER_MAX)
        with _lock:
            istoric_blocari[ip_atacator] = timer_anterior
        _log_response('system',
                      f"IP {ip_atacator} revenit (din DB) — timer dublat: "
                      f"{timer_anterior}s → {timer_nou}s",
                      'BLOCK')
        return timer_nou

    return timer_default

# pentru a putea debloca mai tarziu si ca sa stim IP-ul deja blocat la urmatorea fereastra
def _inregistreaza_blocare(ip_atacator, anomalie, severitate, actiune,
                            container, port=None):
    """Înregistrează o blocare nouă în starea globală."""
    timer = _calculeaza_timer(severitate, ip_atacator)
 
    with _lock:
        blocari_active[ip_atacator] = {
            'timestamp_blocare': time.time(),
            'ultima_anomalie': time.time(),
            'severitate': severitate,
            'actiune': actiune,
            'timer_secunde': timer,
            'container': container,
            'port': port,
            'dispozitiv_victima': anomalie['device'],
            'anomalii_count': 1,
            'incident_id': anomalie.get('incident_id', ''),
        }

def _reseteaza_timer(ip_atacator):
    """Resetează timer-ul unei blocări existente (atacul continuă)."""
    with _lock:
        if ip_atacator in blocari_active:
            blocari_active[ip_atacator]['ultima_anomalie'] = time.time()
            blocari_active[ip_atacator]['anomalii_count'] += 1
            return True
        return False

# parcurge toate blocarile active si deblocheaza cele la care timer-ul a expirat fara anomalii noi
# deizoolarea dispozitivelor
#colectam tot ce trebuie deblocat sub lock, dar executam deblocarea in afara lock-ului
def verifica_blocari_expirate():
    # Colectăm ce trebuie deblocat (sub lock)
    with _lock:
        de_sters = []
        for ip, blocare in blocari_active.items():
            timp_de_la_ultima = time.time() - blocare['ultima_anomalie']
            if timp_de_la_ultima > blocare['timer_secunde']:
                de_sters.append(ip)

    # Deblocăm în afara lock-ului (subprocess calls)
    for ip in de_sters:
        blocare = blocari_active[ip]

        if blocare['actiune'] == 'drop':
            scoate_drop(blocare['container'], ip)
        elif blocare['actiune'] == 'rate_limit':
            scoate_rate_limit(blocare['container'], ip, blocare['port'])

        _log_response(
            blocare['container'],
            f"Blocare EXPIRATĂ: {ip} "
            f"(după {blocare['timer_secunde']}s fără anomalii noi)",
            'UNBLOCK')

        _actualizeaza_incident(blocare['incident_id'],
                               status='expired',
                               deblocat_la=datetime.now().isoformat())

        with _lock:
            istoric_blocari[ip] = blocare['timer_secunde']
            del blocari_active[ip]
        salveaza_istoric_blocare(ip, blocare['timer_secunde'])

    # Verificăm și izolări
    with _lock:
        izolari_de_sters = []
        for container, izolare in izolari_active.items():
            if izolare['timer_secunde'] is None:
                continue
            timp = time.time() - izolare['ultima_anomalie']
            if timp > izolare['timer_secunde']:
                izolari_de_sters.append(container)

    for container in izolari_de_sters:
        deizoleaza_dispozitiv(container)
        with _lock:
            del izolari_active[container]

#thread daemon care ruleaza la infinit - verifica la fiecare 30s functia anterioara
def _thread_verificare_blocari():
    """Thread daemon care verifică periodic blocările expirate."""
    while True:
        time.sleep(TIMER_VERIFICARE)
        try:
            verifica_blocari_expirate()
        except Exception as e:
            print(f"[RESPONSE] Eroare verificare blocări: {e}", flush=True)


# FUNCȚII PENTRU AI (apelate din ai_agent.py)
def actualizeaza_timer_ai(ip_atacator, timer_minute):
    """
    Apelat de AI după analiză — ajustează timer-ul blocării active.
    AI-ul poate extinde (ex: 30 min) sau reduce (ex: 1 min → deblocare rapidă).
    """
    with _lock:
        if ip_atacator in blocari_active:
            timer_nou = min(timer_minute * 60, TIMER_MAX)
            timer_vechi = blocari_active[ip_atacator]['timer_secunde']
            blocari_active[ip_atacator]['timer_secunde'] = timer_nou
            _log_response(
                blocari_active[ip_atacator]['container'],
                f"AI ajustare timer: {ip_atacator} "
                f"{timer_vechi}s → {timer_nou}s",
                'AI')
            return True
    return False

def upgrade_la_drop(ip_atacator):
    """
    Apelat de AI — face upgrade de la rate-limit la DROP complet.
    Folosit când AI-ul decide că severitatea e mai mare decât
    ce a estimat regula locală.
    """
    with _lock:
        if ip_atacator in blocari_active:
            blocare = blocari_active[ip_atacator]
            if blocare['actiune'] == 'rate_limit':
                # Scoatem rate-limit, punem DROP
                scoate_rate_limit(blocare['container'],
                                  ip_atacator, blocare['port'])
                aplica_drop(blocare['container'], ip_atacator)
                blocare['actiune'] = 'drop'
                _log_response(
                    blocare['container'],
                    f"AI upgrade: {ip_atacator} rate-limit → DROP",
                    'AI')
                return True
    return False

def deblocheaza_anticipat(ip_atacator):
    """
    Apelat de AI — deblochează un IP înainte de expirarea timer-ului.
    Folosit când AI-ul decide că e fals pozitiv.
    """
    with _lock:
        if ip_atacator in blocari_active:
            blocare = blocari_active[ip_atacator]
            if blocare['actiune'] == 'drop':
                scoate_drop(blocare['container'], ip_atacator)
            elif blocare['actiune'] == 'rate_limit':
                scoate_rate_limit(blocare['container'],
                                  ip_atacator, blocare['port'])
            _log_response(
                blocare['container'],
                f"AI deblocare anticipată: {ip_atacator}",
                'AI')
            _actualizeaza_incident(blocare['incident_id'],
                                   status='ai_unblocked',
                                   deblocat_la=datetime.now().isoformat())
            del blocari_active[ip_atacator]
            return True
    return False

# SALVARE INCIDENTE (JSON) - in interfata o sa citim aceste pachete
def _salveaza_incident(incident):
    """Salvează un incident în SQLite + JSON (backward compatibility)."""
    # SQLite
    db_salveaza_incident(incident)
    # JSON (păstrăm pentru compatibilitate cu API-ul existent)
    os.makedirs(INCIDENTS_DIR, exist_ok=True)
    filepath = os.path.join(INCIDENTS_DIR, f"{incident['id']}.json")
    with open(filepath, 'w') as f:
        json.dump(incident, f, indent=2, ensure_ascii=False)
 
 
def _actualizeaza_incident(incident_id, **kwargs):
    """Actualizează un incident în SQLite + JSON."""
    if not incident_id:
        return
    # SQLite
    db_actualizeaza_incident(incident_id, **kwargs)
    # JSON (backward compatibility)
    filepath = os.path.join(INCIDENTS_DIR, f"{incident_id}.json")
    if os.path.exists(filepath):
        try:
            with open(filepath) as f:
                incident = json.load(f)
            incident.update(kwargs)
            with open(filepath, 'w') as f:
                json.dump(incident, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

# FUNCȚIA PRINCIPALĂ — PROCESARE RĂSPUNS

def proceseaza_raspuns(rezultate_ecod, ai_callback=None):
    """
    Funcția principală apelată din monitor.py după fiecare fereastră.
 
    Flow:
      1. Filtrează doar anomaliile cu scor > 2×threshold
      2. Grupează pe IP sursă
      3. Clasifică severitate, aplică acțiune imediată
      4. Lansează thread AI paralel (dacă ai_callback e furnizat)
      5. Salvează incident JSON
 
    Args:
        rezultate_ecod: lista de rezultate de la ECOD
        ai_callback: funcția de analiză AI (din ai_agent.py)
                     semnătura: ai_callback(anomalie, incident_id)
 
    Returns:
        list: lista de incidente create
    """
    anomalii = [r for r in rezultate_ecod if r['anomalie']]
 
    if not anomalii:
        return []
 
    incidente = []
 
    # Grupăm anomaliile pe IP sursă unic
    ip_anomalii = {}
    for a in anomalii:
        ip = a['src_ip']
        if ip not in ip_anomalii:
            ip_anomalii[ip] = []
        ip_anomalii[ip].append(a)
 
    for ip_sursa, anomalii_ip in ip_anomalii.items():
 
        # Skip dacă IP-ul e pe trusted list
        if _este_trusted(ip_sursa):
            continue

        # Skip dacă dispozitiv IoT cu anomalii doar pe propriul container
        # (trafic reactiv la un atac, nu atac propriu-zis)
        if ip_sursa in DISPOZITIVE_IOT:
            dst_ips = set(a['dst_ip'] for a in anomalii_ip)
            if not any(dst in DISPOZITIVE_IOT for dst in dst_ips):
                _log_response(anomalii_ip[0]['device'],
                              f"[SKIP] {ip_sursa} — trafic reactiv "
                              f"(răspuns la atacator extern)",
                              'INFO')
                continue
            
        for a in anomalii_ip:
            _adauga_in_istoric(ip_sursa, a['device'], a['scor'])
            # Salvăm în SQLite pentru grafice/statistici
            salveaza_anomalie(
                timestamp=datetime.now().isoformat(),
                sursa_ip=a['src_ip'],
                dst_ip=a['dst_ip'],
                device=a['device'],
                scor=a['scor'],
                threshold=a['threshold'],
                este_anomalie=True,
            )
 
        # Dacă IP-ul e deja blocat, resetăm timer-ul (atacul continuă)
        # Nu lansăm alt thread AI — IP-ul e deja în procesare
        if ip_sursa in blocari_active:
            _reseteaza_timer(ip_sursa)
            continue
 
        # Luăm anomalia cu scorul cel mai mare de la acest IP
        anomalie_max = max(anomalii_ip, key=lambda x: x['scor'])
 
        # Colectăm context
        context = {
            'anomalii_5min': _numar_anomalii_recente(ip_sursa),
            'este_intern': _este_ip_intern(ip_sursa),
            'anomalii_count': len(anomalii_ip),
        }

        # Clasificare severitate
        severitate = calculeaza_severitate(anomalie_max, context)
 
        # Containerul victimă
        device = anomalie_max['device']
        container = DISPOZITIV_CONTAINER.get(device, device)
 
        # Portul atacat
        port = anomalie_max.get('dst_port', 0)
       # Prag de acțiune: scor > 2×threshold
        if anomalie_max['scor'] <= 2 * anomalie_max['threshold']:
            severitate = 'LOG_ONLY'
 
        # ID incident
        incident_id = _genereaza_incident_id()
        anomalie_max['incident_id'] = incident_id
 
        # ── ACȚIUNE IMEDIATĂ ────────────────────────────────────
 
        actiune_luata = None
 
        if severitate == 'HIGH':
            aplica_drop(container, ip_sursa)
            _inregistreaza_blocare(ip_sursa, anomalie_max,
                                   severitate, 'drop', container)
            actiune_luata = 'drop'
 
            # Atac intern → izolăm și atacatorul
            if context['este_intern']:
                container_atacator = _gaseste_container_atacator(ip_sursa)
                if container_atacator:
                    izoleaza_dispozitiv(container_atacator)
                    timer_izolare = _calculeaza_timer(severitate, ip_sursa)
                    izolari_active[container_atacator] = {
                        'timestamp': time.time(),
                        'ultima_anomalie': time.time(),
                        'timer_secunde': timer_izolare,
                        'ip_atacator': ip_sursa,
                    }
 
        elif severitate == 'MEDIUM':
            aplica_rate_limit(container, ip_sursa, port,
                              hits_per_interval=2, interval_sec=10)
            _inregistreaza_blocare(ip_sursa, anomalie_max,
                                   severitate, 'rate_limit',
                                   container, port)
            actiune_luata = 'rate_limit_agresiv'
 
        elif severitate == 'LOW':
            aplica_rate_limit(container, ip_sursa, port,
                              hits_per_interval=5, interval_sec=60)
            _inregistreaza_blocare(ip_sursa, anomalie_max,
                                   severitate, 'rate_limit',
                                   container, port)
            actiune_luata = 'rate_limit_permisiv'
 
        else:
            actiune_luata = 'log_only'
 
 
        # Timer-ul actual (poate fi dublat de la revenire)
        timer_actual = 0
        if ip_sursa in blocari_active:
            timer_actual = blocari_active[ip_sursa]['timer_secunde']
        incident = {
            'id': incident_id,
            'timestamp': datetime.now().isoformat(),
            'sursa_ip': ip_sursa,
            'sursa_tip': 'intern' if context['este_intern'] else 'extern',
            'dispozitiv_victima': device,
            'container_victima': container,
            'scor_ecod': round(anomalie_max['scor'], 2),
            'threshold': round(anomalie_max['threshold'], 2),
            'ratio': round(anomalie_max['scor'] / anomalie_max['threshold'], 2),
            'severitate': severitate,
            'features_anormale': anomalie_max.get('top_features', [])[:3],
            'anomalii_5min': context['anomalii_5min'],
            'anomalii_fereastra': context['anomalii_count'],
            'decizie': actiune_luata,
            'timer_secunde': timer_actual,
            'decizie_sursa': 'rules',
            'ai_verdict': None,
            'status': 'active' if actiune_luata != 'log_only' else 'logged',
        }
 
        _salveaza_incident(incident)
 
        _log_response(device,
                      f"[{severitate}] {ip_sursa} → {actiune_luata} "
                      f"(timer {timer_actual}s) | "
                      f"scor={anomalie_max['scor']:.1f} "
                      f"ratio={incident['ratio']:.1f}",
                      'BLOCK' if 'drop' in str(actiune_luata) else 'RATE')
 
        incidente.append(incident)
 
        # Thread separat per IP — nu blochează monitorizarea
        if ai_callback and actiune_luata != 'log_only':
                    # Context recurență pentru AI
                    anomalie_max['recurenta'] = ip_sursa in istoric_blocari
                    anomalie_max['timer_anterior'] = istoric_blocari.get(ip_sursa, 0)
                    threading.Thread(
                        target=ai_callback,
                        args=(anomalie_max, incident_id),
                        daemon=True,
                        name=f"ai-{ip_sursa}",
                    ).start()
 
    return incidente
 
 
def _gaseste_container_atacator(ip_atacator):
    """Găsește containerul Docker asociat unui IP intern."""
    ip_container = {
        '172.20.0.2':  'gateway',
        '172.20.0.3':  'web_server',
        '172.20.0.4':  'iot_sensor',
        '172.20.0.5':  'auth_server',
        '172.20.0.6':  'smart_camera',
        '172.20.0.7':  'smart_plug',
        '172.20.0.53': 'dns_server',
    }
    return ip_container.get(ip_atacator)
 
 # INIȚIALIZARE — apelat din monitor.py
def init_response():
    """
    Inițializează modulul de răspuns.
    Creează folderele necesare și pornește thread-ul de verificare.
    """
    os.makedirs(INCIDENTS_DIR, exist_ok=True)
    os.makedirs(INCIDENTS_PCAP_DIR, exist_ok=True)
    init_db()
    t = threading.Thread(
        target=_thread_verificare_blocari,
        daemon=True,
        name='response-timer',
    )
    t.start()
 
    print("[RESPONSE] Modul de răspuns inițializat")
    print(f"[RESPONSE] Timer LOW/MEDIUM: {TIMER_LOW_MEDIUM}s | "
          f"Timer HIGH: {TIMER_HIGH}s | "
          f"Verificare: la fiecare {TIMER_VERIFICARE}s")
    print()
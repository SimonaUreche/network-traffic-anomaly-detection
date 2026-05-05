# 🛡️ IoT IDPS — Intrusion Detection & Prevention System for IoT Networks

> **Lucrare de licență** — Sistem de detecție și prevenție a intruziunilor în rețele IoT, cu răspuns automat și analiză AI în timp real.

![Dashboard Overview](docs/screenshots/dashboard-overview.png)

---

## 📋 Descriere

Sistem complet de securitate pentru rețele IoT care detectează anomalii în traficul de rețea folosind algoritmi de machine learning nesupervizat, aplică răspuns automat gradual (rate-limit, DROP, izolare), și analizează atacurile cu un agent AI bazat pe LLM.

### Caracteristici principale

- **Detecție anomalii cu ECOD** — algoritm unsupervised care nu necesită date etichetate de atac
- **Connection tracking bidirecțional** — extractor C care urmărește fluxurile de rețea în ambele direcții (39 features per flux)
- **Răspuns automat gradual** — rate-limiting, DROP iptables, izolare dispozitiv compromis
- **Agent AI** — analiză cu LLM (Llama 3.3 70B via Groq), AbuseIPDB, WHOIS
- **Recurență** — timer dublu la revenirea atacatorului, persistent în SQLite
- **Dashboard real-time** — interfață React cu polling la 3 secunde

---

## 🏗️ Arhitectură

```
┌─────────────────────────────────────────────────────────────────┐
│                        Rețea IoT Docker                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Gateway  │ │Web Server│ │IoT Sensor│ │Auth Serv.│          │
│  │172.20.0.2│ │172.20.0.3│ │172.20.0.4│ │172.20.0.5│          │
│  └────┬─────┘ └──────────┘ └──────────┘ └──────────┘          │
│       │       ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│       │       │Sm. Camera│ │Smart Plug│ │DNS Server│          │
│       │       │172.20.0.6│ │172.20.0.7│ │ 172.20.  │          │
│       │       └──────────┘ └──────────┘ │  0.53    │          │
│       │                                  └──────────┘          │
│  ┌────┴──────────────────────────────────────────────┐         │
│  │              IDPS Monitor (Python)                │         │
│  │  tcpdump → Extractor C → ECOD → Response → AI    │         │
│  └───────────────────────────────────────────────────┘         │
│                         │                                      │
│  ┌──────────────────────┴────────────────────────────┐         │
│  │              Flask API + SQLite                    │         │
│  └───────────────────────┬───────────────────────────┘         │
│                          │                                     │
│  ┌───────────────────────┴───────────────────────────┐         │
│  │              React Dashboard                       │         │
│  └───────────────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📸 Interfață

### Dashboard — Topologie rețea + Amenințări active
<img width="3418" height="1738" alt="image" src="https://github.com/user-attachments/assets/ce8c1eef-f610-4990-b687-c87b6b369956" />

### Incidents — Lista incidentelor cu detalii expandabile
<img width="3348" height="1730" alt="image" src="https://github.com/user-attachments/assets/dc746210-5e70-4b57-ba43-bd48a31bb6a4" />

### Devices — Inventar dispozitive cu status în timp real
<img width="3408" height="1312" alt="image" src="https://github.com/user-attachments/assets/161ce1a5-74ea-4c13-84ad-5ff569d234f2" />

---

## 🔧 Stack tehnologic

| Componentă | Tehnologie |
|---|---|
| Rețea simulată | Docker containers (8 dispozitive IoT) |
| Captură trafic | tcpdump per container |
| Extractor features | **C** (connection tracking bidirecțional, 39 features) |
| Detecție anomalii | **ECOD** (Empirical Cumulative Distribution) |
| Răspuns automat | iptables (DROP, rate-limit, izolare) |
| Agent AI | Groq API (Llama 3.3 70B) + AbuseIPDB + WHOIS |
| Bază de date | SQLite (incidente, istoric blocări, anomalii) |
| API Backend | Flask + flask-cors |
| Frontend | React + Vite + Recharts + Lucide Icons |

---

## 🚀 Instalare și rulare

### Prerequisite

- Docker & Docker Compose
- Python 3.11+
- Node.js 18+
- GCC (pentru compilarea extractorului C)

### 1. Pornire containere Docker

```bash
docker-compose up -d
```

### 2. Compilare extractor C

```bash
cd extractor/build
cmake .. && make clean && make
```

### 3. Antrenare modele ECOD

```bash
# Capturare trafic normal (minim 4-8 ore)
docker exec gateway tcpdump -ni eth0 host 172.20.0.2 -s 96 -w /pcap/normal/gateway_normal.pcap &
# ... (pentru fiecare dispozitiv)

# Extragere features
./extractor/build/extractor pcap/normal/gateway_normal.pcap gateway data/normal/gateway_normal.csv

# Antrenare (Jupyter Notebook)
jupyter notebook ecod_manual.ipynb
```

### 4. Pornire sistem

```bash
# Terminal 1 — API Backend
python api.py

# Terminal 2 — Monitor IDPS
python monitor.py

# Terminal 3 — Frontend Dashboard
cd dashboard-ui && npm run dev
```

### 5. Injectare atacuri (pentru testare)

```bash
# SSH Brute Force (extern)
docker exec external_attacker bash -c '
for i in $(seq 1 30); do
  sshpass -p "parola_${i}" ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=2 root@172.20.0.5 exit 2>/dev/null
done'

# Port Scan (intern — smart_plug compromis)
docker exec smart_plug bash /attack/portscan.sh

# HTTP Flood (extern)
docker exec external_attacker bash -c 'ab -n 200 -c 10 http://172.20.0.3:80/'
```

---

## 📊 Atacuri testate

| # | Atac | Sursă | Țintă | Detecție | Răspuns | AI |
|---|---|---|---|---|---|---|
| 1 | SSH Brute Force | Extern | Auth Server | ✅ ECOD scor 239 | DROP | T1110, AbuseIPDB=100 |
| 2 | HTTP Flood | Extern | Web Server | ✅ ECOD scor 582 | DROP (AI upgrade) | T1499, timer 120min |
| 3 | Slowloris | Extern | Smart Camera | ✅ ECOD scor 252 | DROP | T1190, timer 120min |
| 4 | Port Scan | Intern (Mirai) | Rețea | ✅ ECOD scor 277 | DROP + Izolare | T1046 |
| 5 | DDoS SYN Flood | Intern (Mirai) | Smart Camera | ✅ ECOD scor 176 | DROP + Izolare | T0814 |
| 6 | SSH Brute Force | Intern (Mirai) | Auth Server | ✅ ECOD scor 218 | DROP + Izolare | T1110 |

---

## 🧠 Flow detecție și răspuns

```
Trafic rețea (tcpdump, 10s/fereastră)
    │
    ▼
Extractor C (PCAP → CSV, 39 features bidirecționale)
    │
    ▼
ECOD Scoring (scor anomalie per flux)
    │
    ├── scor ≤ threshold → Normal (skip)
    ├── threshold < scor ≤ 2×threshold → LOG_ONLY
    └── scor > 2×threshold → ACȚIUNE
         │
         ├── ratio < 1.5 → LOW → Rate-limit (5 conn/60s)
         ├── 1.5 ≤ ratio < 3 → MEDIUM → Rate-limit (2 conn/10s)
         └── ratio ≥ 3 → HIGH → DROP iptables
              │
              ├── IP intern → + Izolare dispozitiv (doar MQTT)
              └── Thread AI paralel (2-3s):
                   ├── AbuseIPDB check
                   ├── WHOIS lookup
                   ├── LLM analysis (Groq)
                   └── Ajustare timer / upgrade acțiune
```

---

## 📁 Structura proiectului

```
thesis-project/
├── extractor/              # Extractor C (connection tracking)
│   ├── include/
│   │   ├── flow_table.h
│   │   ├── csv_writer.h
│   │   └── packet_parser.h
│   └── src/
│       ├── main.c
│       ├── flow_table.c
│       └── csv_writer.c
├── models/                 # Modele ECOD antrenate
├── data/normal/            # CSV-uri trafic normal
├── pcap/normal/            # Capturi PCAP
├── incidents/              # Incidente JSON (backup)
├── docker/                 # Dockerfiles + scripturi atac
│   └── smart_plug/attack/
│       ├── portscan.sh
│       ├── ddos.sh
│       └── bruteforce.sh
├── dashboard-ui/           # React frontend
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx
│       │   ├── Incidents.jsx
│       │   └── Devices.jsx
│       └── components/
│           └── NetworkTopology.jsx
├── monitor.py              # Monitorizare principală
├── inference.py             # Inferență ECOD
├── response.py              # Răspuns automat + iptables
├── ai_agent.py              # Agent AI (AbuseIPDB + WHOIS + LLM)
├── database.py              # SQLite (incidente, istoric, anomalii)
├── api.py                   # Flask API pentru dashboard
├── ecod_manual.ipynb        # Antrenare modele ECOD
├── docker-compose.yml
└── idps.db                  # Baza de date SQLite
```

---

## 🔑 Configurare API Keys

Sistemul necesită chei API pentru:

| Serviciu | Scop | Gratuit |
|---|---|---|
| [Groq](https://console.groq.com/) | LLM (Llama 3.3 70B) | ✅ Da |
| [AbuseIPDB](https://www.abuseipdb.com/) | Threat Intelligence | ✅ Da (1000 req/zi) |

Configurează în `ai_agent.py`:
```python
GROQ_API_KEY = "gsk_..."
ABUSEIPDB_KEY = "..."
```

---

## 📚 Referințe

- **ECOD** — Li, Z. et al. (2022). *ECOD: Unsupervised Outlier Detection Using Empirical Cumulative Distribution Functions*. IEEE TKDE.
- **MITRE ATT&CK** — Framework de clasificare atacuri (T1110, T1046, T1499, T1190)
- **CICFlowMeter** — Inspirație pentru extragerea features de rețea
- **Suricata / Snort** — Referință pentru connection tracking stateful

---

## 👩‍💻 Autor

**Simona Ureche** — Universitatea Tehnică, Facultatea de Automatică și Calculatoare

Lucrare de licență, 2026

---

## 📄 Licență

Acest proiect este dezvoltat exclusiv în scop academic, ca parte a lucrării de licență.

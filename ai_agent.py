import requests
import subprocess
import json
import time
from datetime import datetime
from response import (
    actualizeaza_timer_ai,
    upgrade_la_drop,
    deblocheaza_anticipat,
    _actualizeaza_incident,
    _log_response,
    _numar_anomalii_recente,
    _este_ip_intern,
    blocari_active,
)
import os

ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'your_abuseipdb_api_key_here')
GROQ_API_KEY = os.getenv('GROQ_API_KEY', 'your_groq_api_key_here')

# Mapare IP-uri simulate → IP-uri reale pentru AbuseIPDB
# IP-urile interne/private nu există în AbuseIPDB, așa că le mapăm
# la IP-uri publice reale pentru a demonstra integrarea
IP_SIMULAT_LA_REAL = {
    "172.20.0.99": "92.118.39.235"
    }

# Topologia rețelei — context pentru LLM
TOPOLOGIE_RETEA = """
Rețeaua IoT monitorizată (Docker containers):
- 172.20.0.2  = gateway (MQTT broker mosquitto, rutare, SSH health check la auth_server la 45s)
- 172.20.0.3  = web_server (nginx HTTP)
- 172.20.0.4  = iot_sensor (client MQTT, trimite temperatură la 8-12s)
- 172.20.0.5  = auth_server (SSH server, primește health check de la gateway)
- 172.20.0.6  = smart_camera (client MQTT la 15s + HTTP firmware check la 150s + nginx config UI)
- 172.20.0.7  = smart_plug (client MQTT la 30s — POATE FI COMPROMIS, scenariul Mirai)
- 172.20.0.8  = honeypot (niciun serviciu activ)
- 172.20.0.53 = dns_server (dnsmasq)

Comunicări normale cunoscute:
- gateway ↔ auth_server:22 (SSH health check la 45s)
- gateway ↔ web_server:80 (HTTP la 5s)
- gateway ↔ dns_server:53 (DNS query-uri)
- iot_sensor → gateway:1883 (MQTT la 8-12s)
- smart_camera → gateway:1883 (MQTT la 15s)
- smart_camera → web_server:80 (firmware check la 150s)
- smart_plug → gateway:1883 (MQTT la 30s)

IP-uri externe (atacatori prin socat tunnel):
- 172.20.0.1 = IP-ul gateway-ului Docker bridge (traficul din Kali Linux VM apare cu acest IP)
"""

def check_abuseipdb(ip):
    ip_lookup = IP_SIMULAT_LA_REAL.get(ip, ip)

    if ip_lookup.startswith(('172.', '192.168.', '10.')):
        return {
            'score': -1,
            'country': 'LOCAL',
            'isp': 'Rețea internă IoT',
            'total_reports': 0,
            'is_tor': False,
            'ip_verificat': ip_lookup,
            'ip_original': ip,
            'nota': 'IP intern',
        }

    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip_lookup, 'maxAgeInDays': 90},
            timeout=10,
        )
        data = r.json()['data']
        return {
            'score': data.get('abuseConfidenceScore', 0),
            'country': data.get('countryCode', 'N/A'),
            'isp': data.get('isp', 'N/A'),
            'total_reports': data.get('totalReports', 0),
            'is_tor': data.get('isTor', False),
            'ip_verificat': ip_lookup,
            'ip_original': ip,
        }
    except Exception as e:
        _log_response('AI', f"Eroare AbuseIPDB: {e}", 'AI')
        return {'score': -1, 'country': 'error', 'isp': 'error', 'total_reports': 0, 'is_tor': False, 'ip_verificat': ip_lookup, 'ip_original': ip}



def whois_lookup(ip):
    if _este_ip_intern(ip):
        return {
            'organization': 'Rețea internă IoT (Docker)',
            'country': 'LOCAL',
            'netname': 'iot_network',
        }
    ip_lookup = IP_SIMULAT_LA_REAL.get(ip, ip)

    try:
        result = subprocess.run(
            ['whois', ip_lookup],
            capture_output=True,
            text=True,
            timeout=10,
        )

        org = country = netname = ''
        for line in result.stdout.split('\n'):
            line_lower = line.lower()
            if ('orgname:' in line_lower or 'org-name:' in line_lower) and not org:
                org = line.split(':', 1)[1].strip()
            elif 'country:' in line_lower and not country:
                country = line.split(':', 1)[1].strip()
            elif 'netname:' in line_lower and not netname:
                netname = line.split(':', 1)[1].strip()

        return {
            'organization': org or 'unknown',
            'country': country or 'unknown',
            'netname': netname or 'unknown',
        }
    except Exception as e:
        return {
            'organization': 'error',
            'country': 'error',
            'netname': 'error',
            'nota': f'Eroare WHOIS: {e}',
        }


SYSTEM_PROMPT = f"""Ești un analist de securitate specializat pe rețele IoT.
Primești date de la un sistem ECOD de detecție a anomaliilor, împreună cu
informații din surse de threat intelligence (AbuseIPDB, WHOIS).

{TOPOLOGIE_RETEA}

Analizează anomalia și decide:
1. Tipul atacului și maparea MITRE ATT&CK
2. Severitatea (critica/medie/scazuta)
3. Timer-ul de blocare recomandat (în minute)

Ghid pentru timer:
- 1-3 min: probabil fals pozitiv, deblocare rapidă
- 5-10 min: anomalie ambiguă, monitorizare
- 15-30 min: atac confirmat dar izolat
- 60 min: atac confirmat cu intelligence extern (AbuseIPDB > 50)
- 120-360 min: atac sever cu confirmare multiplă
- 1440 min (24h): IP cu scor AbuseIPDB > 80 sau nod Tor confirmat

Timer-ul e punctul de start — dacă atacul continuă, sistemul îl dublează automat.
Dacă anomalia e de la un dispozitiv propriu al rețelei (gateway, auth_server etc.)
și pare a fi trafic reactiv la un atac extern, recomandă timer scurt (1-3 min)
sau deescaladare.

Limbă și stil (obligatoriu):
- Toate câmpurile destinate operatorului uman trebuie scrise în limba română:
  "tip_atac", "explicatie", "recomandari" (fiecare element din listă).
- Folosește diacritice corecte: ă, â, î, ș, ț (ex.: rețea, blocare, nu "retea"/"Blokare").
- "recomandari": exact 3 până la 5 acțiuni concrete, scurte (max. ~120 caractere fiecare),
  formulate ca recomandări operaționale (imperativ sau infinitiv scurt), adaptate la tipul atacului
  și la dispozitivul victimă. Fără text generic de tip "verificare generală" fără obiect.
- Nu repeta aceeași idee în mai multe puncte. Nu amesteca engleza în recomandări decât pentru
  termeni tehnici inevitabili (ex.: SSH, MQTT, IP).

Răspunde STRICT cu JSON valid, fără markdown, fără backticks, fără text extra.
Doar obiectul JSON, nimic altceva."""


def analiza_llm(anomalie, abuse_result, whois_result):
    """
    Trimite contextul complet la Groq (Llama 3.3 70B) și primește analiză.
    """
    features_text = ""
    for f in anomalie.get('top_features', [])[:3]:
        features_text += (f"{f.get('feature','?')}="
                         f"{f.get('valoare','?')} "
                         f"(z={f.get('zscore','?')}σ), ")

    anomalii_5min = _numar_anomalii_recente(anomalie['src_ip'])

    user_prompt = f"""Analizează această anomalie detectată de ECOD:

ANOMALIE:
- IP sursă: {anomalie['src_ip']} ({'intern' if _este_ip_intern(anomalie['src_ip']) else 'extern'})
- IP destinație: {anomalie['dst_ip']}
- Port destinație: {anomalie.get('dst_port', '?')}
- Dispozitiv victimă: {anomalie['device']}
- Scor ECOD: {anomalie['scor']:.1f} (threshold: {anomalie['threshold']:.1f}, ratio: {anomalie['scor'] / anomalie['threshold']:.1f}x)
- Features anormale: {features_text or 'N/A'}

THREAT INTELLIGENCE:
- AbuseIPDB: scor={abuse_result.get('score', 'N/A')}, country={abuse_result.get('country', 'N/A')}, ISP={abuse_result.get('isp', 'N/A')}, rapoarte={abuse_result.get('total_reports', 'N/A')}, Tor={abuse_result.get('is_tor', False)}
- WHOIS: organizație={whois_result.get('organization', 'N/A')}, country={whois_result.get('country', 'N/A')}

CONTEXT REȚEA:
- Anomalii de la acest IP în ultimele 5 min: {anomalii_5min}

Răspunde cu JSON (chei exacte):
{{"tip_atac": "scurt, în română", "mitre_ids": ["Txxxx"], "mitre_names": ["Nume tactică MITRE în engleză e acceptabil"], "severitate": "critica|medie|scazuta", "confidence": 0.0-1.0, "timer_recomandat_minute": numar, "explicatie": "2-4 propoziții în română, fără redundanță", "recomandari": ["3-5 string-uri în română, cu diacritice, acțiuni concrete"]}}"""

    try:
        r = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {GROQ_API_KEY}',
                'Content-Type': 'application/json',
            },
            json={
                'model': 'llama-3.3-70b-versatile',
                'messages': [
                    {'role': 'system', 'content': SYSTEM_PROMPT},
                    {'role': 'user', 'content': user_prompt},
                ],
                'temperature': 0.1,
                'max_tokens': 500,
            },
            timeout=15,
        )

        response_text = r.json()['choices'][0]['message']['content']

        # Curățăm markdown dacă LLM-ul pune backticks
        clean = response_text.strip()
        if clean.startswith('```'):
            clean = clean.split('\n', 1)[1]
            clean = clean.rsplit('```', 1)[0].strip()

        return json.loads(clean)

    except json.JSONDecodeError as e:
        _log_response('AI', f"Eroare parsare JSON de la LLM: {e}", 'AI')
        _log_response('AI', f"Răspuns brut: {response_text[:200]}", 'AI')
        return _fallback_verdict(anomalie, abuse_result)
    except Exception as e:
        _log_response('AI', f"Eroare Groq API: {e}", 'AI')
        return _fallback_verdict(anomalie, abuse_result)


def _fallback_verdict(anomalie, abuse_result):
    """Verdict de fallback dacă LLM-ul nu răspunde corect."""
    ratio = anomalie['scor'] / anomalie['threshold']
    abuse_score = abuse_result.get('score', 0)
    dst_port = anomalie.get('dst_port', 0)

    if dst_port == 22:
        tip = "Forță brută SSH"
        mitre = "T1110"
    elif dst_port == 80:
        tip = "Flood HTTP"
        mitre = "T1499"
    elif dst_port == 1883:
        tip = "Flood MQTT"
        mitre = "T1071"
    else:
        tip = "Scanare rețea"
        mitre = "T1046"

    if abuse_score >= 80:
        timer = 1440
        sev = "critica"
    elif ratio >= 3:
        timer = 30
        sev = "critica"
    elif ratio >= 1.5:
        timer = 10
        sev = "medie"
    else:
        timer = 3
        sev = "scazuta"

    recs = [
        'Menține politica de blocare/rate-limit conform severității curente.',
        'Revizuiește jurnalele pe dispozitivul victimă și corelează cu alte alerte.',
    ]
    if dst_port == 22:
        recs.insert(0, 'Verifică autentificarea SSH (chei, parole, încercări eșuate).')
    elif dst_port in (80, 1883):
        recs.insert(0, 'Monitorizează volumul de trafic și sursele către serviciul afectat.')

    return {
        'tip_atac': tip,
        'mitre_ids': [mitre],
        'mitre_names': [tip],
        'severitate': sev,
        'confidence': 0.5,
        'timer_recomandat_minute': timer,
        'explicatie': (
            f'Analiză de rezervă (fără LLM): incident clasificat ca {tip}, '
            f'raport scor/threshold {ratio:.1f}x. Verifică manual detaliile.'
        ),
        'recomandari': recs[:5],
        'nota': 'FALLBACK — LLM nu a răspuns corect',
    }


def analiza_ai(anomalie, incident_id):
    ip_sursa = anomalie['src_ip']
    device = anomalie['device']

    _log_response(device, f"AI analiză pornită: {ip_sursa}", 'AI')

    start_time = time.time()

    # ── PAS 1: AbuseIPDB ────────────────────────────────────────
    abuse_result = check_abuseipdb(ip_sursa)
    _log_response(device,
                  f"AbuseIPDB: {ip_sursa} → "
                  f"scor={abuse_result.get('score', 'N/A')}, "
                  f"country={abuse_result.get('country', '?')}, "
                  f"ISP={abuse_result.get('isp', '?')}, "
                  f"rapoarte={abuse_result.get('total_reports', 0)}, "
                  f"Tor={abuse_result.get('is_tor', False)}",
                  'AI')

    # ── PAS 2: WHOIS ────────────────────────────────────────────
    whois_result = whois_lookup(ip_sursa)
    _log_response(device,
                  f"WHOIS: {ip_sursa} → "
                  f"org={whois_result.get('organization', '?')}, "
                  f"country={whois_result.get('country', '?')}",
                  'AI')

    # ── PAS 3: Groq LLM ────────────────────────────────────────
    ai_verdict = analiza_llm(anomalie, abuse_result, whois_result)

    elapsed = time.time() - start_time

    _log_response(device,
                  f"AI verdict ({elapsed:.1f}s): "
                  f"{ai_verdict.get('tip_atac', '?')} | "
                  f"sev={ai_verdict.get('severitate', '?')} | "
                  f"timer={ai_verdict.get('timer_recomandat_minute', '?')} min | "
                  f"MITRE={ai_verdict.get('mitre_ids', [])}",
                  'AI')

    _log_response(device,
                  f"AI explicație: {ai_verdict.get('explicatie', 'N/A')}",
                  'AI')

    # ── PAS 4: Aplică decizia AI ────────────────────────────────

    timer_ai = ai_verdict.get('timer_recomandat_minute', 5)
    severitate_ai = ai_verdict.get('severitate', 'medie')

    # Ajustare timer
    actualizeaza_timer_ai(ip_sursa, timer_ai)

    # Upgrade la DROP dacă AI zice critică și era rate-limit
    if severitate_ai == 'critica':
        upgrade_la_drop(ip_sursa)

    # Deblocare anticipată dacă AI zice scăzută cu confidence mare
    if (severitate_ai == 'scazuta' and
            ai_verdict.get('confidence', 0) > 0.8):
        _log_response(device,
                      f"AI recomandă deblocare: {ip_sursa} "
                      f"(fals pozitiv, confidence {ai_verdict['confidence']:.0%})",
                      'AI')
        deblocheaza_anticipat(ip_sursa)

    # ── PAS 5: Update incident JSON ─────────────────────────────
    _actualizeaza_incident(
        incident_id,
        ai_verdict=ai_verdict,
        abuseipdb=abuse_result,
        whois=whois_result,
        decizie_sursa='ai_updated',
        ai_elapsed_seconds=round(elapsed, 2),
    )

    _log_response(device,
                  f"AI analiză completă: {ip_sursa} → "
                  f"timer ajustat la {timer_ai} min",
                  'AI')
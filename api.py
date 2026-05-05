"""
api.py — Flask API pentru dashboard-ul IoT IDPS

Servește date din:
  - SQLite (idps.db) — sursa principală
  - incidents/*.json — fallback
  - response.py — blocări active în memorie (dacă monitor.py rulează)

Rulare:
    python api.py
    
Endpoint-uri:
    GET /api/incidents          — toate incidentele
    GET /api/incidents/<id>     — detalii incident
    GET /api/blocks             — blocări active
    GET /api/devices            — status dispozitive
    GET /api/stats              — statistici aggregate
    GET /api/timeline           — timeline AI interventions
    GET /api/anomalii           — anomalii recente (pentru grafic live)
    GET /api/historic           — istoric blocări (recurență)
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import json
import glob
import time
from datetime import datetime
from database import (
    init_db,
    get_toate_incidentele,
    get_incidente_active,
    get_incident,
    get_anomalii_recente,
    get_anomalii_per_device,
    get_tot_istoricul_blocari,
    get_istoric_blocare,
    get_statistici,
)

app = Flask(__name__)
CORS(app)

INCIDENTS_DIR = 'incidents'

# Topologia rețelei
DEVICES = {
    'gateway': {
        'name': 'Gateway',
        'ip': '172.20.0.2',
        'role': 'MQTT Broker & Router',
        'icon': 'router',
    },
    'web_server': {
        'name': 'Web Server',
        'ip': '172.20.0.3',
        'role': 'Nginx HTTP Server',
        'icon': 'server',
    },
    'iot_sensor': {
        'name': 'IoT Sensor',
        'ip': '172.20.0.4',
        'role': 'Temperature Sensor (MQTT)',
        'icon': 'thermometer',
    },
    'auth_server': {
        'name': 'Auth Server',
        'ip': '172.20.0.5',
        'role': 'SSH Authentication Server',
        'icon': 'lock',
    },
    'smart_camera': {
        'name': 'Smart Camera',
        'ip': '172.20.0.6',
        'role': 'IP Camera (MQTT + HTTP)',
        'icon': 'camera',
    },
    'smart_plug': {
        'name': 'Smart Plug',
        'ip': '172.20.0.7',
        'role': 'Smart Power Outlet (MQTT)',
        'icon': 'plug',
    },
    'dns_server': {
        'name': 'DNS Server',
        'ip': '172.20.0.53',
        'role': 'DNS Resolution (dnsmasq)',
        'icon': 'globe',
    }
}

IP_TO_DEVICE = {info['ip']: name for name, info in DEVICES.items()}


def _get_active_blocks():
    """
    Citește blocările active din response.py (dacă monitor.py rulează).
    Fallback: deduce din incidentele cu status='active'.
    """
    try:
        from response import blocari_active, izolari_active
        blocks = []
        for ip, info in blocari_active.items():
            elapsed = time.time() - info['ultima_anomalie']
            remaining = max(0, info['timer_secunde'] - elapsed)
            blocks.append({
                'ip': ip,
                'device': IP_TO_DEVICE.get(ip, 'unknown'),
                'actiune': info['actiune'],
                'severitate': info['severitate'],
                'container': info['container'],
                'dispozitiv_victima': info['dispozitiv_victima'],
                'timer_secunde': info['timer_secunde'],
                'remaining_secunde': round(remaining),
                'anomalii_count': info['anomalii_count'],
                'incident_id': info['incident_id'],
            })

        isolations = []
        for container, info in izolari_active.items():
            elapsed = time.time() - info['ultima_anomalie']
            remaining = max(0, (info['timer_secunde'] or 0) - elapsed)
            isolations.append({
                'container': container,
                'ip_atacator': info['ip_atacator'],
                'timer_secunde': info['timer_secunde'],
                'remaining_secunde': round(remaining),
            })

        return {'blocks': blocks, 'isolations': isolations}
    except Exception:
        # Fallback: deducem din SQLite
        incidents = get_incidente_active()
        blocks = []
        for inc in incidents:
            blocks.append({
                'ip': inc['sursa_ip'],
                'actiune': inc['decizie'],
                'severitate': inc['severitate'],
                'container': inc.get('container_victima', ''),
                'dispozitiv_victima': inc.get('dispozitiv_victima', ''),
                'timer_secunde': inc.get('timer_secunde', 0),
                'remaining_secunde': 0,
                'anomalii_count': inc.get('anomalii_fereastra', 0),
                'incident_id': inc['id'],
            })
        return {'blocks': blocks, 'isolations': []}


def _get_device_status():
    """Determină statusul fiecărui dispozitiv din SQLite."""
    incidents = get_incidente_active()
    active_blocks = _get_active_blocks()

    blocked_ips = {b['ip'] for b in active_blocks['blocks']}
    isolated_containers = {i['container'] for i in active_blocks['isolations']}

    victim_devices = set()
    for inc in incidents:
        victim_devices.add(inc.get('dispozitiv_victima', ''))

    devices_status = []
    for name, info in DEVICES.items():
        ip = info['ip']

        if name in isolated_containers:
            status = 'isolated'
        elif ip in blocked_ips:
            status = 'blocked'
        elif name in victim_devices:
            status = 'alert'
        else:
            status = 'online'

        recent_incidents = sum(1 for inc in incidents
                               if inc.get('sursa_ip') == ip)

        last_incident = None
        all_incidents = get_toate_incidentele()
        for inc in all_incidents:
            if (inc.get('sursa_ip') == ip or
                    inc.get('dispozitiv_victima') == name):
                last_incident = inc['id']
                break

        current_action = 'none'
        # Verificăm dacă acest dispozitiv e victimă protejată
        for b in active_blocks['blocks']:
            if b['dispozitiv_victima'] == name:
                current_action = b['actiune']
                break
            if b['ip'] == ip:
                current_action = b['actiune']
                break
        if name in isolated_containers:
            current_action = 'isolated'

        devices_status.append({
            **info,
            'device_id': name,
            'status': status,
            'incidents_recent': recent_incidents,
            'current_action': current_action,
            'last_incident': last_incident,
        })

    return devices_status


def _get_ai_timeline():
    """Generează timeline-ul intervențiilor AI din SQLite."""
    incidents = get_toate_incidentele()
    timeline = []

    for inc in incidents:
        ai = inc.get('ai_verdict')
        if ai:
            timeline.append({
                'timestamp': inc['timestamp'],
                'incident_id': inc['id'],
                'action': 'ai_analysis',
                'sursa_ip': inc['sursa_ip'],
                'dispozitiv_victima': inc.get('dispozitiv_victima', ''),
                'decizie_initiala': inc['decizie'],
                'ai_severitate': ai.get('severitate', ''),
                'ai_tip_atac': ai.get('tip_atac', ''),
                'ai_timer_min': ai.get('timer_recomandat_minute', 0),
                'ai_mitre': ai.get('mitre_ids', []),
                'ai_confidence': ai.get('confidence', 0),
                'ai_explicatie': ai.get('explicatie', ''),
                'ai_elapsed': inc.get('ai_elapsed_seconds', 0),
                'abuseipdb_score': inc.get('abuseipdb', {}).get('score', -1) if inc.get('abuseipdb') else -1,
            })

    return sorted(timeline, key=lambda x: x['timestamp'], reverse=True)

@app.route('/api/incidents', methods=['GET'])
def api_incidents():
    """Returnează toate incidentele din SQLite."""
    incidents = get_toate_incidentele()
    return jsonify({
        'count': len(incidents),
        'incidents': incidents,
    })


@app.route('/api/incidents/active', methods=['GET'])
def api_incidents_active():
    """Returnează doar incidentele active."""
    incidents = get_incidente_active()
    return jsonify({
        'count': len(incidents),
        'incidents': incidents,
    })


@app.route('/api/incidents/<incident_id>', methods=['GET'])
def api_incident_detail(incident_id):
    """Returnează detalii pentru un incident specific."""
    incident = get_incident(incident_id)
    if incident is None:
        return jsonify({'error': 'Incident not found'}), 404
    return jsonify(incident)


@app.route('/api/blocks', methods=['GET'])
def api_blocks():
    """Returnează blocările active și izolările."""
    return jsonify(_get_active_blocks())


@app.route('/api/devices', methods=['GET'])
def api_devices():
    """Returnează statusul tuturor dispozitivelor."""
    devices = _get_device_status()
    return jsonify({
        'count': len(devices),
        'devices': devices,
    })


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Returnează statistici aggregate din SQLite."""
    stats = get_statistici()
    active_blocks = _get_active_blocks()

    # Healthy nodes
    devices = _get_device_status()
    healthy = sum(1 for d in devices if d['status'] == 'online')

    return jsonify({
        'total_incidents': stats.get('total_incidente', 0),
        'active_incidents': stats.get('incidente_active', 0),
        'active_blocks': len(active_blocks['blocks']),
        'active_isolations': len(active_blocks['isolations']),
        'severity': {
            'high': stats.get('incidente_high', 0),
            'medium': stats.get('incidente_medium', 0),
            'low': stats.get('incidente_low', 0),
            'log_only': stats.get('incidente_log_only', 0),
        },
        'avg_ai_response': stats.get('avg_ai_response', 0),
        'healthy_nodes': f"{healthy}/{len(DEVICES)}",
        'atacatori_unici': stats.get('atacatori_unici', 0),
        'recurente': stats.get('recurente', 0),
    })


@app.route('/api/timeline', methods=['GET'])
def api_timeline():
    """Returnează timeline-ul intervențiilor AI."""
    timeline = _get_ai_timeline()
    return jsonify({
        'count': len(timeline),
        'timeline': timeline,
    })


@app.route('/api/anomalii', methods=['GET'])
def api_anomalii():
    """Returnează anomaliile recente (pentru grafic live)."""
    minute = request.args.get('minute', 30, type=int)
    anomalii = get_anomalii_recente(minute)
    per_device = get_anomalii_per_device(minute)
    return jsonify({
        'count': len(anomalii),
        'anomalii': anomalii,
        'per_device': per_device,
    })


@app.route('/api/historic', methods=['GET'])
def api_historic():
    """Returnează istoricul blocărilor (pentru recurență)."""
    historic = get_tot_istoricul_blocari()
    return jsonify({
        'count': len(historic),
        'historic': historic,
    })


if __name__ == '__main__':
    init_db()
    os.makedirs(INCIDENTS_DIR, exist_ok=True)
    print("IoT IDPS Dashboard API")
    print("Sursa date: SQLite (idps.db)")
    print("http://localhost:5001")
    print()
    app.run(host='0.0.0.0', port=5001, debug=True)
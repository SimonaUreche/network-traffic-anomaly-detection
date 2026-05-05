"""
inference.py — Modul de inferență ECOD pentru detecția anomaliilor IoT

Folosește modelele antrenate în ecod_manual.ipynb pentru a evalua
fluxuri noi de rețea și a detecta anomalii.

Utilizare:
    from inference import incarca_modele, proceseaza_csv

    modele = incarca_modele('models/')
    rezultate = proceseaza_csv('live/gateway_live.csv', 'gateway', modele)
"""

import numpy as np
import pandas as pd
import joblib
import json
import os


EPSILON = 1e-10  # evităm log(0) la calculul scorurilor
FEATURE_COLS = [
    'fwd_total_packets', 'fwd_total_bytes',
    'fwd_avg_pkt_size', 'fwd_std_pkt_size', 'fwd_min_pkt_size', 'fwd_max_pkt_size',
    'fwd_avg_iat', 'fwd_std_iat',
    'fwd_syn_count', 'fwd_ack_count', 'fwd_fin_count', 'fwd_rst_count', 'fwd_psh_count',
    'rev_total_packets', 'rev_total_bytes',
    'rev_avg_pkt_size', 'rev_std_pkt_size', 'rev_min_pkt_size', 'rev_max_pkt_size',
    'rev_avg_iat', 'rev_std_iat',
    'rev_syn_count', 'rev_ack_count', 'rev_fin_count', 'rev_rst_count', 'rev_psh_count',
    'flow_duration', 'total_packets', 'total_bytes',
    'fwd_rev_packet_ratio', 'fwd_rev_byte_ratio',
    'unique_dst_ips', 'unique_dst_ports', 'connection_degree', 'dst_entropy',
    'is_standard_port', 'is_internal_only', 'is_night_traffic', 'is_known_pair',
]

def ecdf_stanga(z, X_train_col):
    return np.mean(X_train_col <= z)


def ecdf_dreapta(z, X_train_col):
    return np.mean(X_train_col >= z)


def calculeaza_scoruri_vectorizat(X_eval, model):
    X_train = model['X_train']  
    gamma = model['gamma']    
    m, d  = X_eval.shape
    n = X_train.shape[0]

    termeni_left  = np.zeros((m, d))
    termeni_right = np.zeros((m, d))

    for j in range(d):
        col_train = X_train[:, j]
        col_eval = X_eval[:, j]

        # Vectorizare F̂_left pentru toate cele m fluxuri simultan
        mat_stanga = col_train[np.newaxis, :] <= col_eval[:, np.newaxis]
        p_left     = mat_stanga.mean(axis=1)

        # Vectorizare F̂_right pentru toate cele m fluxuri simultan
        mat_dreapta = col_train[np.newaxis, :] >= col_eval[:, np.newaxis]
        p_right     = mat_dreapta.mean(axis=1)

        p_left  = np.maximum(p_left,  EPSILON)
        p_right = np.maximum(p_right, EPSILON)

        termeni_left[:, j] = -np.log(p_left)
        termeni_right[:, j] = -np.log(p_right)

    #O_left, O_right, O_auto pentru toate cele m fluxuri simultan
    O_left  = termeni_left.sum(axis=1)
    O_right = termeni_right.sum(axis=1)
    masca_dreapta = (gamma >= 0)
    termeni_auto  = np.where(masca_dreapta, termeni_right, termeni_left)
    O_auto        = termeni_auto.sum(axis=1)

    #max dintre cele 3
    O_final = np.maximum(np.maximum(O_left, O_right), O_auto)

    return O_final, termeni_auto


def calculeaza_scoruri_batched(X_eval, model, batch_size=500):
    m = X_eval.shape[0]
    O_final_all = np.zeros(m)
    contrib_all = np.zeros((m, X_eval.shape[1]))

    for start in range(0, m, batch_size):
        end   = min(start + batch_size, m)
        batch = X_eval[start:end]

        O_batch, contrib_batch = calculeaza_scoruri_vectorizat(batch, model)
        O_final_all[start:end] = O_batch
        contrib_all[start:end] = contrib_batch

    return O_final_all, contrib_all



def incarca_modele(model_dir='models'):
    registry_path = os.path.join(model_dir, 'registry.json')

    if not os.path.exists(registry_path):
        raise FileNotFoundError(f"Nu gasesc {registry_path}. ")

    with open(registry_path) as f:
        registry = json.load(f)

    modele_incarcate = {}

    for device, paths in registry.items():
        model = joblib.load(paths['model'])
        with open(paths['metadata']) as f:
            metadata = json.load(f)

        modele_incarcate[device] = {'model': model, 'metadata': metadata,}

        print(f"{device:15s}  threshold={metadata['threshold']:.3f}  "f"n_train={metadata['n_train']:,}")

    return modele_incarcate


def proceseaza_csv(csv_path, device, modele):
    if device not in modele:
        print(f"Dispozitiv necunoscut: {device}")
        return []

    if not os.path.exists(csv_path):
        print(f"CSV lipsă: {csv_path}")
        return []

    df = pd.read_csv(csv_path)

    initial = len(df)

    # Excludem ICMP/ARP — port 0 pe ambele capete
    # avg_iat=5s pe ICMP produce false positives sistematice
    if 'src_port' in df.columns and 'dst_port' in df.columns:
        df = df[~((df['src_port'] == 0) & (df['dst_port'] == 0))]

    # Excludem fluxuri de 1 pachet — artefacte de captură
    # Toate atacurile relevante produc 2+ pachete
    if 'total_packets' in df.columns:
        df = df[df['total_packets'] > 1]

    eliminate = initial - len(df)

    if eliminate > 0:
        print(f"[{device}] Filtrate {eliminate} fluxuri triviale")

    if len(df) < 2:
        print(f"[{device}] Prea puține fluxuri după filtrare ({len(df)}) — skip")
        return []

    if len(df) == 0:
        # fereastra fara trafic - la inceput
        return []

    model = modele[device]['model']
    metadata = modele[device]['metadata']
    threshold = metadata['threshold']
    feature_names = metadata['feature_names']

    cols_disponibile = [c for c in feature_names if c in df.columns]
    cols_lipsa = [c for c in feature_names if c not in df.columns]

    if cols_lipsa:
        print(f"{device}: coloane lipsă din CSV: {cols_lipsa}")
        for col in cols_lipsa:
            df[col] = 0.0
    X_eval = df[feature_names].fillna(0).clip(lower=0).values.astype(np.float64)
    O_final, contributii = calculeaza_scoruri_batched(X_eval, model)

    print(f"[{device}] scor min={O_final.min():.2f} max={O_final.max():.2f} thr={threshold:.2f}")

    rezultate = []

    for i in range(len(df)):
        rand = df.iloc[i]
        scor = float(O_final[i])

        flux_meta = {
            'src_ip'  : str(rand.get('src_ip',   'N/A')),
            'dst_ip'  : str(rand.get('dst_ip',   'N/A')),
            'src_port': int(rand.get('src_port', 0)),
            'dst_port': int(rand.get('dst_port', 0)),
            'protocol': int(rand.get('protocol', 0)),
        }

        top5 = top_features_anormale(
            contributii[i],
            feature_names,
            X_eval[i],
            metadata['train_stats'],
        )

        rezultate.append({
            'device'      : device,
            **flux_meta,
            'scor'        : scor,
            'threshold'   : threshold,
            'anomalie'    : scor > threshold,
            'top_features': top5,
        })

    return rezultate


def top_features_anormale(contributii_flux, feature_names, valori_flux, train_stats, top_n=5):
    mean_normal = np.array(train_stats['mean'])
    std_normal  = np.array(train_stats['std'])

    std_safe = np.where(std_normal == 0, 1.0, std_normal)

    top = []
    for j in np.argsort(contributii_flux)[::-1][:top_n]:
        valoare  = float(valori_flux[j])
        medie    = float(mean_normal[j])
        std      = float(std_normal[j])

        # Z-score: câte deviații standard e valoarea față de media normală
        # +12 înseamnă că valoarea e cu 12σ mai mare decât media normală
        zscore = (valoare - medie) / std_safe[j]

        top.append({
            'feature'    : feature_names[j],
            'valoare'    : round(valoare, 4),
            'medie_normala': round(medie, 4),
            'std_normala': round(std, 4),
            'zscore'     : round(float(zscore), 2),
            'contributie': round(float(contributii_flux[j]), 4),
        })

    return top


if __name__ == '__main__':
    import sys

    try:
        modele = incarca_modele('models')
    except FileNotFoundError as e:
        print(f"EROARE: {e}")
        sys.exit(1)

    for device in modele:
        csv_test = f"data/normal/{device}_normal.csv"

        if not os.path.exists(csv_test):
            print(f"{device}: CSV lipsa")
            continue

        print(f"\nTestez pe {device} ({csv_test})...")

        df_test = pd.read_csv(csv_test).head(10)
        csv_tmp = f"/tmp/{device}_test.csv"
        df_test.to_csv(csv_tmp, index=False)

        rezultate = proceseaza_csv(csv_tmp, device, modele)

        anomalii = [r for r in rezultate if r['anomalie']]
        normale  = [r for r in rezultate if not r['anomalie']]

        if rezultate:
            r = rezultate[0]
            print(f"\n  Exemplu flux 1:")
            print(f"    Scor     : {r['scor']:.3f}")
            print(f"    Threshold: {r['threshold']:.3f}")
            print(f"    Anomalie : {r['anomalie']}")
            print(f"    Top feature: {r['top_features'][0]['feature']} "
                  f"(val={r['top_features'][0]['valoare']}, "
                  f"z={r['top_features'][0]['zscore']:+.1f}σ)")

    print("\n=== Test complet ===")
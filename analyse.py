"""Projet 1 - Analyse des journaux d'un pare-feu.

Usage : python analyse.py
Lit data/logs_reseau.csv, nettoie les donnees, calcule les resultats,
enregistre les figures dans figures/ et ecrit resultats.json.
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # pas besoin d'ecran
import matplotlib.pyplot as plt
import pandas as pd

RACINE = Path(__file__).resolve().parent
DONNEES = RACINE / "data" / "logs_reseau.csv"
FIGURES = RACINE / "figures"
RESULTATS = RACINE / "resultats.json"


def charger_et_nettoyer(chemin: Path) -> pd.DataFrame:
    """Lit le CSV puis applique les 3 etapes de nettoyage de l'enonce."""
    df = pd.read_csv(chemin, parse_dates=["timestamp"])
    df = df.drop_duplicates()                              # 1. doublons exacts
    df["protocol"] = df["protocol"].str.upper()            # 2. casse
    mediane = df["bytes_sent"].median()                    # 3. mediane apres doublons
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)
    return df.reset_index(drop=True)


def calculer_resultats(df: pd.DataFrame) -> dict:
    """Calcule les 5 indicateurs demandes."""
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(df.groupby("src_ip")["dst_port"].nunique().idxmax()),
        "ip_exfiltration": str(df.groupby("src_ip")["bytes_sent"].sum().idxmax()),
    }


def _enregistrer(fig, nom: str) -> None:
    fig.tight_layout()
    fig.savefig(FIGURES / nom, dpi=120)
    plt.close(fig)


def tracer_figures(df: pd.DataFrame, res: dict) -> None:
    FIGURES.mkdir(exist_ok=True)

    # 1. Top 10 des ports de destination
    fig, ax = plt.subplots(figsize=(8, 5))
    top = df["dst_port"].value_counts().head(10)
    ax.bar(top.index.astype(str), top.values, color="#3b6fb6")
    ax.set_title("Top 10 des ports de destination")
    ax.set_xlabel("Port de destination")
    ax.set_ylabel("Nombre de connexions")
    _enregistrer(fig, "01_top_ports.png")

    # 2. Repartition ALLOW / DENY
    fig, ax = plt.subplots(figsize=(6, 6))
    rep = df["action"].value_counts()
    couleurs = ["#4c9f70" if a == "ALLOW" else "#d1495b" for a in rep.index]
    ax.pie(rep.values, labels=rep.index, autopct="%1.1f%%", colors=couleurs, startangle=90)
    ax.set_title("Repartition des connexions ALLOW / DENY")
    _enregistrer(fig, "02_allow_deny.png")

    # 3. Octets envoyes par type d'appareil (echelle log)
    fig, ax = plt.subplots(figsize=(8, 5))
    vol = df.groupby("device_type")["bytes_sent"].sum().sort_values(ascending=False)
    ax.bar(vol.index, vol.values, color="#e08e2b")
    ax.set_yscale("log")
    ax.set_title("Volume d'octets envoyes par type d'appareil (echelle log)")
    ax.set_xlabel("Type d'appareil")
    ax.set_ylabel("Octets envoyes (total)")
    _enregistrer(fig, "03_octets_par_appareil.png")

    # 4. Connexions par heure
    fig, ax = plt.subplots(figsize=(9, 5))
    par_heure = df.groupby(df["timestamp"].dt.hour).size()
    ax.plot(par_heure.index, par_heure.values, marker="o", color="#3b6fb6")
    ax.set_xticks(range(0, 24))
    ax.set_title("Nombre de connexions par heure de la journee")
    ax.set_xlabel("Heure")
    ax.set_ylabel("Nombre de connexions")
    ax.grid(alpha=0.3)
    _enregistrer(fig, "04_connexions_par_heure.png")

    # 5. Ports distincts contactes par source (detection du scanner)
    fig, ax = plt.subplots(figsize=(9, 5))
    ports = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(8)
    couleurs = ["#d1495b" if ip == res["ip_scanner"] else "#8aa4c8" for ip in ports.index]
    ax.bar(ports.index, ports.values, color=couleurs)
    ax.set_title("Ports distincts contactes par adresse source (top 8)")
    ax.set_xlabel("Adresse IP source")
    ax.set_ylabel("Nombre de ports distincts")
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    _enregistrer(fig, "05_scan_ports.png")

    # 6. Octets envoyes par source (detection de l'exfiltration)
    fig, ax = plt.subplots(figsize=(9, 5))
    octets = df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(8)
    couleurs = ["#d1495b" if ip == res["ip_exfiltration"] else "#8aa4c8" for ip in octets.index]
    ax.bar(octets.index, octets.values, color=couleurs)
    ax.set_yscale("log")
    ax.set_title("Octets envoyes par adresse source (top 8, echelle log)")
    ax.set_xlabel("Adresse IP source")
    ax.set_ylabel("Octets envoyes (total)")
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    _enregistrer(fig, "06_exfiltration.png")


def main() -> None:
    df = charger_et_nettoyer(DONNEES)
    res = calculer_resultats(df)
    RESULTATS.write_text(json.dumps(res, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tracer_figures(df, res)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"Figures enregistrees dans {FIGURES}")


if __name__ == "__main__":
    main()

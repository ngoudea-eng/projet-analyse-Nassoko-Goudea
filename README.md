# Projet 1 — Analyse des journaux d'un pare-feu

**Auteur : Goudea Nassoko** — ngoudea@gmail.com

Analyse d'une semaine de connexions d'un pare-feu (5 500 lignes brutes) pour détecter des comportements suspects
sur un réseau composé de PC, serveurs et objets connectés.

## Lancer le projet

```bash
pip install -r requirements.txt
python analyse.py
```

Le script lit `data/logs_reseau.csv`, nettoie les données, génère `resultats.json` et les graphiques dans `figures/`.

## Contenu

| Fichier | Rôle |
|---|---|
| `analyse.py` | nettoyage, calcul des résultats, figures |
| `resultats.json` | les 5 indicateurs (générés par le script) |
| `figures/*.png` | 6 graphiques |
| `rapport.md` | rapport d'analyse, comportements suspects, recommandations |

## Résultats

| Indicateur | Valeur |
|---|---|
| Lignes après nettoyage | 5 440 |
| Port le plus fréquent | 443 |
| Taux de DENY | 13,57 % |
| IP scanner | 192.168.1.99 |
| IP exfiltration | 192.168.1.11 |

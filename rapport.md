# Rapport d'analyse des journaux du pare-feu

**Auteur : Goudea Nassoko** · Période analysée : du 5 au 11 octobre 2026

## Résumé

Après nettoyage (60 doublons supprimés, protocoles mis en majuscules, 166 `bytes_sent` manquants remplacés par la
médiane de 1 710 octets), il reste **5 440 connexions**. Le trafic est dominé par HTTPS (port 443, 1 874 connexions)
puis HTTP (80), DNS (53) et MQTT (1883, objets connectés). **13,57 %** des connexions sont bloquées (DENY). Deux
comportements sortent clairement du lot : un **scan de ports** par un PC interne et une **fuite de données
probable** depuis une caméra IoT.

## Comportements suspects

### 1. Scan de ports depuis 192.168.1.99 (PC)

- **328 ports distincts** contactés, contre 8 au maximum pour toutes les autres machines (figure `05_scan_ports.png`).
- 400 connexions toutes dirigées vers le serveur `10.0.0.5`, concentrées en **15 minutes**
  (le 8 octobre entre 00:00 et 00:15), sur des ports de 9 à 1023.
- **383 de ces 400 connexions (95,8 %) ont été bloquées** par le pare-feu : le scan a été en grande partie
  stoppé, mais 17 connexions ont été autorisées, donc certains ports du serveur ont répondu.
- Un PC qui scanne un serveur en pleine nuit est typique d'une reconnaissance : machine compromise ou utilisateur malveillant.

### 2. Exfiltration de données depuis 192.168.1.11 (caméra IoT)

- Cette caméra a envoyé **≈ 260 Mo** (259 932 541 octets), soit **94,7 % de tout le volume sortant** du réseau,
  alors que les autres machines envoient environ 0,6 Mo chacune (figure `06_exfiltration.png`).
- Le volume vient de **38 transferts de plus de 1 Mo** (jusqu'à 8,7 Mo) tous le **10 octobre**, vers `8.8.8.8` sur
  le port **8080**, alors qu'une caméra n'envoie normalement que quelques ko.
- La figure `03_octets_par_appareil.png` confirme que les caméras IoT représentent à elles seules ≈ 262 Mo, loin devant les PC, capteurs et serveurs.
- Ces transferts ont été **autorisés** (185 connexions ALLOW sur 194) : la caméra est probablement compromise
  et sert à sortir des données.

### Autres observations

- Telnet (port 23), protocole non chiffré, reste utilisé : 100 connexions provenant de 29 machines, dont 74 bloquées.
- RDP (3389) : 111 tentatives, 81 bloquées (73 %), ce qui évoque des tentatives d'accès à distance.

## Recommandations

1. **Segmenter le réseau** : placer les objets IoT (caméras, capteurs) dans un VLAN dédié, sans accès direct aux serveurs.
2. **Filtrer le trafic sortant** : n'autoriser les caméras que vers leur serveur d'enregistrement et le broker MQTT ; bloquer le port 8080 sortant et tout transfert vers Internet non justifié.
3. **Isoler et inspecter 192.168.1.11 et 192.168.1.99** : couper leur accès réseau, analyser ou réinstaller les machines, changer les mots de passe par défaut de la caméra et mettre à jour son firmware.
4. **Fermer Telnet (23)** sur tout le réseau et le remplacer par SSH avec authentification par clé ; limiter RDP (3389) à un VPN.
5. **Détection et alertes** : règle IDS/pare-feu qui alerte au-delà de ~20 ports distincts par source en quelques minutes (scan) et au-delà de 1 Mo par connexion sortante pour un appareil IoT.
6. **Journaliser et centraliser** les logs (SIEM) pour réagir rapidement, y compris la nuit.

# Lab 1 - Navigation HTTPS : DNS, handshake TCP, fuite SNI

Capture d'un `curl https://example.com` analysée dans Wireshark.
**Objectif :** distinguer ce qui circule en clair de ce qui est chiffré.

**Capture :**
```bash
sudo tcpdump -i any -w lab1_dns_https.pcap 'port 53 or host 172.66.147.243 
or host 104.20.23.154'
curl -v https://example.com
```

---

## 1. Résolution DNS
<img width="1568" height="319" alt="image" src="https://github.com/user-attachments/assets/4eac94d7-3c26-4bcb-9e0f-5dd990f05e8b" />


Le client interroge le stub local `127.0.0.53` (systemd-resolved), relayé 
vers `192.168.182.1`.
Requêtes `A` (IPv4) + `AAAA` (IPv6) en parallèle ; plusieurs A renvoyées 
(CDN Cloudflare), une seule utilisée.
Réponse appariée à la requête par le **Transaction ID** (`0x8b78`).

## 2. Handshake TCP
<img width="1400" height="857" alt="image" src="https://github.com/user-attachments/assets/495c40b9-c9d4-408c-b724-7d40efb73f74" />


`119 SYN → 125 SYN-ACK → 126 ACK`. Établissement de la connexion en 3 
temps : chaque sens
annonce son numéro de séquence et confirme celui de l'autre, avant tout 
échange de données.

## 3. Client Hello - fuite SNI
<img width="1400" height="857" alt="image" src="https://github.com/user-attachments/assets/1432fce6-7845-4d8d-a834-07e0dc2cb2ca" />


Paquet 144 : `Client Hello (SNI=example.com)` en **clair**. Le contenu sera 
chiffré, mais le
**nom du domaine visité fuite**. Un observateur (FAI, SOC, attaquant) sait 
quel site est contacté
sans rien déchiffrer → **source de détection** (repérer un domaine 
malveillant même en HTTPS).

## 4. Données chiffrées + fermeture
<img width="1400" height="857" alt="image" src="https://github.com/user-attachments/assets/63b6c6ae-315d-48d7-b084-bd65eb764890" />


Dès le `Server Hello` (150), tout est chiffré : `Application Data` = 
taille/timing visibles,
contenu non. Fermeture propre : `FIN, ACK` (196/202) puis `ACK`.

---

## Incident de capture : les 2 routes par défaut
Première capture : DNS présent mais **0 trafic HTTPS**. Cause :
```
default via 10.0.3.2    dev enp0s8  metric 101     <-- internet 
(prioritaire)
default via 192.168.182.1 dev enp0s3  metric 20100 <-- DNS
```
Je capturais `enp0s3`, mais le HTTPS sortait par `enp0s8`. **Leçon : la 
mauvaise interface = angle
mort, un trafic entier passe hors surveillance.** Correctif : `-i any`.

## Limites
Le SNI en clair est **normal** (TLS hors ECH), pas une anomalie en soi. Une 
capture mono-interface
peut faire croire à tort que « rien ne se passe ».

# OSI & TCP/IP - HTB Network Fundamentals

## Les 7 couches OSI

| # | Nom | PDU | Exemples |
|:---:|:---|:---|:---|
| 7 | Application | Data | HTTP, DNS, FTP, SSH |
| 6 | Présentation | Data | TLS, SSL |
| 5 | Session | Data | Sessions |
| 4 | Transport | Segment / Datagramme | TCP, UDP |
| 3 | Réseau | Paquet | IP, ICMP |
| 2 | Liaison | Trame | Ethernet, MAC |
| 1 | Physique | Bits | Câbles, Wi-Fi |

**Couches 2-4** = transport oriented  **Couches 5-7** = application 
oriented
**OSI** = théorique, pour analyser et diagnostiquer  **TCP/IP** = ce qui 
tourne réellement sur internet

## Encapsulation

Chaque couche ajoute un en-tête. À la réception → désencapsulation inverse.

`Couche 7 → "GET / HTTP/1.1" → Couche 4 [TCP] → Couche 3 [IP] → Couche 2 
[MAC] → Couche 1 : 01001000... (binaire)`

## Voyage d'un paquet

**IP** → ne change jamais de bout en bout - **MAC** → change à chaque saut 
— **ARP** → traduit l'IP du prochain saut en MAC (local uniquement) — 
**NAT** → remplace l'IP privée par l'IP publique avant internet

## TCP vs UDP vs ICMP

| Protocole | Handshake | Ports | Usage |
|:---|:---|:---|:---|
| TCP | SYN/SYN-ACK/ACK | Oui | HTTP, FTP, SSH |
| UDP | Non | Oui | DNS, streaming |
| ICMP | Non | Non | Ping, traceroute |

## Flux complet — facebook.com

`DNS (UDP) → résout l'IP → TCP handshake port 443 → TLS handshake → HTTP 
GET → page reçue`

## Attaques par couche OSI

| Attaque | Couche |
|:---|:---|
| DDoS | 3/4 |
| ARP spoofing | 2 |
| SQLi / XSS | 7 |


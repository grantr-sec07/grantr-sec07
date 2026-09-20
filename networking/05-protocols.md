# 05-protocols.md - Common Protocols & Ports

## TCP vs UDP (Couche Transport - L4)
* **TCP (Connection-Oriented) :** Handshake à 3 temps (`SYN` -> `SYN-ACK` -> 
`ACK`). Fiable, contrôle de flux, réémission.
* **UDP (Connectionless) :** Pas de handshake, envoi direct. Rapide, faible 
overhead, aucune garantie de livraison.

---

## Services TCP courants

| Protocole | Port | Description / Usage SecOps |
|:---|:---|:---|
| **FTP** | 20 / 21 | Transfert de fichiers (20=Data, 21=Control) |
| **SSH** | 22 | Administration à distance chiffrée |
| **Telnet** | 23 | Administration non chiffrée (Texte clair) |
| **SMTP** | 25 | Envoi de courriels (Relais de messagerie) |
| **DNS** | 53 | Transferts de zone (AXFR) et requêtes > 512 octets |
| **HTTP / HTTPS** | 80 / 443 | Flux Web (HTTP clair / HTTPS TLS) |
| **Kerberos** | 88 | Authentification (Active Directory) |
| **POP3 / IMAP** | 110 / 143 | Relève de courriels (Cleartext) |
| **SMB** | 445 | Partage de fichiers & RPC Windows |
| **LDAP / LDAPS** | 389 / 636 | Annuaire Active Directory (Cleartext / TLS) 
|
| **MySQL / MSSQL** | 3306 / 1433 | Bases de données relationnelles |
| **RDP** | 3389 | Bureau à distance Windows |

---

## Services UDP courants

| Protocole | Port | Description / Usage SecOps |
|:---|:---|:---|
| **DNS** | 53 | Résolution de noms standard (Requêtes rapides) |
| **DHCP** | 67 (Server) / 68 (Client) | Attribution dynamique d'IP |
| **TFTP** | 69 | Transfert de fichiers léger sans authentification |
| **NTP** | 123 | Synchronisation horaire (Crucial pour Kerberos) |
| **SNMP** | 161 / 162 | Supervision d'équipements réseau |
| **Syslog** | 514 | Journalisation réseau centralisée |

---

## ICMP - Internet Control Message Protocol
* **Pas de port** (Fonctionne directement au-dessus d'IP - Protocol 1).
* Utilisé pour la gestion d'erreurs et le diagnostic L3.

| Type ICMP | Nom | Usage |
|:---|:---|:---|
| **Type 8 / Type 0** | Echo Request / Reply | Commande `ping` |
| **Type 3** | Destination Unreachable | Port/Hôte ou réseau inaccessible |
| **Type 11** | Time Exceeded | TTL expiré à 0 (Mécanisme de `traceroute`) |

### OS Fingerprinting via le TTL (Time To Live)
Chaque saut de routeur décrémente le TTL de 1.

| OS | TTL par défaut |
|:---|:---|
| **Linux / Android / macOS** | 64 |
| **Windows** | 128 |
| **Solaris / Cisco** | 255 |

> **Exemple :** Ping reçu avec un TTL de `122`.  
> $128 - 122 = 6$ sauts de routeur  Target initiale probable = **Windows**.

---

## VoIP & SIP
* **Ports :** TCP/UDP 5060 (SIP) | TCP 5061 (SIP-TLS) | TCP 1720 (H.323).
* **Méthodes SIP clés :** `INVITE` (appel), `BYE` (raccrocher), `OPTIONS` 
(demande de fonctionnalités).
* **Vecteurs d'attaque :** Énumération d'utilisateurs via `OPTIONS`, 
brute-force d'extensions téléphonique, interception de fichiers de 
configuration (`SEP<MAC>.cnf`).

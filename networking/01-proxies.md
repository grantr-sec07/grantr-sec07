# Proxys - HTB Network Fundamentals

## C'est quoi un proxy ?
Un intermédiaire qui **inspecte le trafic** applicatif (Couche 7 OSI), contrairement à une simple passerelle qui se contente de le transporter.

---

## Les 3 types
* **Forward Proxy (direct) :** `Toi -> Proxy -> Internet`
  * Protège le client interne et filtre le trafic sortant.
  * Exemple : Squid en entreprise, Burp Suite en pentest.
* **Reverse Proxy (inverse) :** `Internet -> Proxy -> Ton serveur`
  * Protège les serveurs web et masque leur existence.
  * Exemple : Cloudflare (Anti-DDoS), ModSecurity (WAF).
* **Transparent vs Non-transparent :**
  * *Transparent :* Invisible pour l'utilisateur, configuré au niveau réseau.
  * *Non-transparent :* Nécessite une configuration explicite dans l'app/OS.

---

## Outils clés
| Outil | Type | Usage |
| :--- | :--- | :--- |
| **Burp Suite** | Forward / Reverse | Intercepter et modifier les requêtes HTTP |
| **Chisel / Sshuttle** | SOCKS / SSH | Pivoter et traverser un réseau interne |
| **Cloudflare** | Reverse Proxy | Anti-DDoS, masquer l'IP d'origine |
| **ModSecurity** | WAF (Reverse) | Bloquer les attaques web (SQLi, XSS, LFI) |

---

## Points sécurité
* **Proxy vs VPN :** Le proxy inspecte la couche 7 (HTTP), le VPN chiffre et route au niveau réseau (couche 3).
* **Malwares & Proxy Aware :**
  * Via **WinSock** (API Windows) -> le malware hérite automatiquement du proxy système.
  * Via **libcurl** (ex: Firefox) -> il ignore le proxy système par défaut, ce qui peut bloquer ses communications vers l'extérieur.
* **Pivotement :** Un attaquant peut poser un reverse proxy sur une machine compromise pour rediriger ses flux à travers des tunnels autorisés (ex: SSH).



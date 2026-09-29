# Fiche - Commandes Linux d'investigation

Boîte à outils d'analyste, construite à partir des labs du Bloc 1.
**Méthode :** partir de l'indice → remonter jusqu'à une preuve → 
corroborer.

Chaîne type d'une investigation :
`indice réseau → processus → binaire réel → hash (IOC) → logs / lignée`

---

## 1. Réseau - connexions actives
| Commande | Rôle |
|---|---|
| `ss -tanp` | Lister les connexions TCP + le **processus** derrière (PID). 
Le point de départ. |
| `ss -tanp \| grep :4444` | Isoler une connexion sur un port suspect. |

`-t` TCP · `-a` toutes · `-n` numérique · `-p` processus.
États clés : `ESTAB` = connexion active **maintenant**.

## 2. Processus - fiche d'identité
| Commande | Rôle |
|---|---|
| `ps -o pid,ppid,user,comm,args -p <PID>` | PID, **PPID** (parent), 
utilisateur, nom, **ligne de commande complète**. |
| `ps aux \| grep <nom>` | Chercher un processus par son nom (découverte 
large). |

Le PPID permet de **remonter la lignée** (qui a lancé le processus : shell ? 
cron ? service ?).

## 3. Binaire / fichier - vérité et empreinte
| Commande | Rôle |
|---|---|
| `ls -l /proc/<PID>/exe` | Voir le **vrai binaire** exécuté (le nom du 
process peut mentir, pas le noyau). |
| `readlink /proc/<PID>/exe` | Idem, mais renvoie **juste le chemin** (pour 
l'utiliser dans une commande). |
| `sudo sha256sum /proc/<PID>/exe` | **Hash (IOC)** du binaire — marche même 
si le fichier a été supprimé du disque ! |

Drapeau rouge : un binaire exécuté depuis `/tmp` (zone temporaire 
inscriptible par tous).

## 4. Logs - authentification & services
| Commande | Rôle |
|---|---|
| `sudo grep sshd /var/log/auth.log` | Événements SSH. |
| `sudo grep "Failed password" /var/log/auth.log` | Échecs de connexion. |
| `sudo grep "Accepted" /var/log/auth.log` | Connexions réussies. |
| `journalctl -u ssh --since "10 min ago"` | Journal systemd du service, 
fenêtre temporelle. |

Réflexe : **filtrer** (`grep`) au lieu de dérouler à l'aveugle (`tail`).
Corréler : même IP source + même user + méthode.

## 5. Capture réseau
| Commande / filtre | Rôle |
|---|---|
| `sudo tcpdump -i any -w capture.pcap 'port 53 or host <IP>'` | Capturer 
(toutes interfaces → pas d'angle mort). |
| `dns` | Voir la résolution A (IPv4) / AAAA (IPv6). |
| `tcp.flags.syn == 1` | Le handshake TCP (SYN / SYN-ACK / ACK). |
| `tls.handshake.type == 1` | Le **Client Hello** → le SNI (nom de domaine) 
en clair. |
| `tcp.port == 443` | Isoler le trafic d'un port. |

## 6. Scan de ports
| Commande | Rôle |
|---|---|
| `sudo nmap -sS -p 22,80,3306 <IP>` | SYN scan (half-open, furtif, requiert 
root). |
| `nmap -sT -p 22,80,3306 <IP>` | Connect scan (handshake complet, sans 
root, plus bruyant). |
| `sudo nmap -sS --reason -p ... <IP>` | Affiche la **raison** de chaque 
verdict. |
| `sudo ufw status verbose` | Vérifier les règles du pare-feu (côté 
défense). |

Lecture des états : **open** = `syn-ack` (service écoute) · **closed** = 
`reset` (machine répond, pas de service) · **filtered** = `no-response` 
(pare-feu jette en silence).

# Lab 3 - Scan Nmap : ports ouvert / fermé / filtré + effet d'un pare-feu

Scan d'une VM Ubuntu depuis Kali, comparaison SYN scan / Connect scan, et 
démonstration
de l'effet d'un pare-feu (`ufw`) sur la lecture des états de ports.

- **Cible :** Ubuntu `192.168.183.204`
- **Scanner :** Kali (`nmap 7.95`)
- **Ports testés :** 22 (SSH), 80 (HTTP), 23 (telnet), 3306 (MySQL)

---

## 1. Les 3 états d'un port
- **open** → le port répond `SYN-ACK` (un service écoute).
- **closed** → le port répond `RST` (aucun service, mais la machine est 
joignable).
- **filtered** → **aucune réponse** (un pare-feu jette le paquet en 
silence).

Un port n'est `open` que si **deux** conditions sont réunies : un service 
écoute **et** le
pare-feu laisse passer le paquet jusqu'à lui.

## 2. Scan initial (SYN scan) - une anomalie
```bash
sudo nmap -sS --reason -p 22,80,23,3306 192.168.183.204
```
_(capture : 22 open / 80,23,3306 filtered)_

<img width="592" height="310" alt="image" src="https://github.com/user-attachments/assets/99b2795c-ba88-48ab-8d17-259563ef60f7" />


Résultat : `22 open` (`syn-ack`), mais `80`, `23`, `3306` en **filtered** 
(`no-response`).
Le `80` était attendu `open` (un service y écoute) → **anomalie** : quelque 
chose drope les paquets.

## 3. Investigation - le pare-feu
```bash
sudo ufw status verbose        # sur l'Ubuntu
```
_(capture : règles ufw)_

<img width="928" height="516" alt="image" src="https://github.com/user-attachments/assets/a7d4ed6c-313a-49cb-bcb9-d16b8839eaa4" />

ufw est **actif**, politique par défaut `deny (incoming)` :
- `22/tcp ALLOW IN` → le 22 passe → **open**
- `80/tcp DENY IN` → le 80 est dropé → **filtered** (alors qu'un service 
écoute)
- `23`, `3306` : aucune règle → **default deny** → **filtered**

Cause trouvée : le pare-feu autorise le 22 et jette le reste.

## 4. Avant / après (firewall OFF)
```bash
sudo ufw disable               # sur l'Ubuntu (test)
sudo nmap -sS --reason -p 22,80,23,3306 192.168.183.204   # sur Kali
sudo ufw enable                # on remet la protection
```
_(capture : 22,80 open / 23,3306 closed)_

<img width="592" height="310" alt="image" src="https://github.com/user-attachments/assets/967b8cdc-161c-480d-9e39-afd0ee75bd96" />

| Port | ufw ON | ufw OFF | Réalité |
|---|---|---|---|
| 22 | open | open | service SSH |
| 80 | filtered | **open** (`syn-ack`) | service web **caché** par le firewall |
| 23 | filtered | **closed** (`reset`) | aucun service |
| 3306 | filtered | **closed** (`reset`) | aucun service |

**Leçon clé :** le pare-feu transforme un `open` (80) ET des `closed` 
(23/3306) en un même
`filtered` indistinct → il cache la réalité à l'attaquant. C'est son rôle défensif.

## 5. SYN scan vs Connect scan
```bash
sudo nmap -sS ...   # SYN : handshake à moitié, requiert root, furtif
nmap -sT ...        # Connect : handshake complet, sans root, plus bruyant 
(logué)
```
Même verdict sur les états ; ce qui change c'est la **méthode** (half-open vs complet), les
**droits** (root ou non) et la **discrétion** (le Connect complète la connexion → plus de traces).

## 6. Notes
- Un scan **n'est pas un DoS** : il envoie quelques paquets par port pour 
lire un état ;
  un DoS inonde pour épuiser la cible. Volume et intention différents.
- Côté défense (SOC) : un scan adverse = nombreuses tentatives sur des ports 
variés en peu de
  temps → **détectable** dans les logs / le SIEM (signal de 
reconnaissance).
- `--reason` donne l'évidence derrière chaque verdict (`syn-ack` / `reset` / 
`no-response`).

# Lab 2 - Investigation SSH : échecs puis réussite (brute force aboutie)

Génération d'un scénario « 3 échecs SSH puis 1 réussite » sur une VM Ubuntu, 
puis
investigation via les logs système et corrélation multi-sources.

- **Cible :** Ubuntu `192.168.183.204` (serveur SSH, port 22)
- **Source :** `192.168.183.146` (poste attaquant)
- **Compte visé :** `fonfon`

---

## 1. Génération du comportement
Depuis la source, 3 tentatives avec un mauvais mot de passe puis 1 avec le 
bon :
```bash
ssh fonfon@192.168.183.204   # x3 mauvais mot de passe
ssh fonfon@192.168.183.204   # bon mot de passe → connecté
```

## 2. Traces dans `/var/log/auth.log`
_(capture : les 3 `Failed password` + le `Accepted password`)_

```
21:17:31  Failed password   for fonfon from 192.168.183.146 port 55509 ssh2
21:17:44  Failed password   for fonfon from 192.168.183.146 port 55509 ssh2
21:17:55  Failed password   for fonfon from 192.168.183.146 port 55509 ssh2
21:17:55  Connection closed by authenticating user fonfon ... 55509 
[preauth]
21:18:14  Accepted password for fonfon from 192.168.183.146 port 55511 ssh2
21:18:14  New session 882 of user fonfon
```


**Corrélation :** même compte (`fonfon`), même IP source 
(`192.168.183.146`), méthode
**password** → les 3 échecs et la réussite forment un même incident.

**Piège écarté :** une ligne `Accepted publickey for fonfon from 127.0.0.1` 
(tâche CRON locale)
apparaît dans la même fenêtre. Elle **ne fait pas partie** de l'incident : 
mauvaise IP source
(127.0.0.1) et mauvaise méthode (publickey). On ne corrèle que ce qui a la 
même IP + user + méthode.

<img width="1568" height="503" alt="image" src="https://github.com/user-attachments/assets/3a962794-8940-47e0-8e9d-c58f5babeb7a" />

**Note :** le port source change (55509 → 55511) car chaque connexion `ssh` 
ouvre un nouveau
port éphémère. La corrélation se fait sur l'IP/compte, pas sur le port.

## 3. Confirmation multi-sources
_(capture : sorties `last`, `who`, `ss`)_

| Source | Ce qu'elle confirme |
|---|---|
| `last -a` | `fonfon pts/2 21:18 still logged in 192.168.183.146` → 
session réussie |
| `who` | `fonfon pts/2 21:18 (192.168.183.146)` → session active |
| `sudo ss -tapn` | `ESTAB 192.168.183.204:22 ← 192.168.183.146:55511` (PID 
sshd 25714) → connexion vivante |

Le **port 55511** relie les trois sources : log, historique de connexion, 
état réseau en direct.
Trois angles indépendants concordent → fait établi.

## 4. Détection & réponse
- **Détection :** N échecs suivis d'une réussite, même IP + même compte, 
dans une courte fenêtre
  → motif de **brute force aboutie** (règle SIEM à écrire au Bloc 3).
- **Réponse :** vérifier si l'utilisateur est légitime ; sinon contenir — 
réinitialiser le mot de
  passe, terminer la session, auditer les actions réalisées après la 
connexion.

## 5. Limites / faux positifs
- Un utilisateur qui se trompe 2-3 fois de mot de passe puis réussit produit 
le **même motif** →
  d'où l'importance du contexte (IP connue ? horaire ? volume ?).
- Ici l'IP source est locale et connue ; en production, une IP externe 
inconnue élèverait la sévérité.

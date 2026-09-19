## Subnetting

**Adresse réseau** → tous les bits hôtes à 0
**Broadcast** → tous les bits hôtes à 1
**Hôtes disponibles** → 2^n - 2 (n = bits hôtes)

**Trouver le block size (méthode modulo) :**
CIDR % 8 = reste → 2^(8-reste) = block size

| CIDR | Calcul | Block size | Hôtes dispo |
|:---|:---|:---|:---|
| /25 | 2^7 | 128 | 126 |
| /26 | 2^6 | 64 | 62 |
| /27 | 2^5 | 32 | 30 |
| /28 | 2^4 | 16 | 14 |
| /29 | 2^3 | 8 | 6 |

**Quel octet change ?**
/8 → 1er octet — /16 → 2ème — /24 → 3ème — au-delà → 4ème

**Exemple complet — 192.168.12.160/26 :**
Block size = 64 → blocs : 0, 64, **128**, 192
160 tombe dans le bloc 128

| | Adresse |
|:---|:---|
| Réseau | 192.168.12.128 |
| Premier hôte | 192.168.12.129 |
| Dernier hôte | 192.168.12.190 |
| Broadcast | 192.168.12.191 |
| Hôtes dispo | 62 |

**Diviser 10.200.20.0/27 en 4 sous-réseaux :**
32 / 4 = 8 → nouveau block size → /29

| Sous-réseau | Réseau | Broadcast |
|:---|:---|:---|
| 1 | 10.200.20.0/29 | 10.200.20.7 |
| 2 | 10.200.20.8/29 | 10.200.20.15 |
| 3 | 10.200.20.16/29 | 10.200.20.23 |
| 4 | 10.200.20.24/29 | 10.200.20.31 |

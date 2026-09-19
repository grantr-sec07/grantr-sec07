# Subnetting & CIDR — HTB Network Fundamentals

## Définitions clés

* **Adresse réseau :** Tous les bits hôtes mis à 0 (non attribuable).
* **Broadcast :** Tous les bits hôtes mis à 1 (diffusion globale au 
sous-réseau).
* **Hôtes exploitables :** $2^n - 2$ (où $n$ = nombre de bits hôtes 
réservés).

---

## Calcul mental rapide (Méthode Modulo)

1. **Quel octet varie ?**
   * `/8` → 1er octet
   * `/16` → 2ème octet
   * `/24` → 3ème octet
   * `/25` à `/32` → 4ème octet

2. **Taille du bloc (Block Size) :** `CIDR % 8 = reste` → **`Block Size = 
2^(8 - reste)`**

| CIDR | Calcul | Block Size | Hôtes exploitables |
|:---:|:---:|:---:|:---:|
| **/25** | $2^7$ | 128 | 126 |
| **/26** | $2^6$ | 64 | 62 |
| **/27** | $2^5$ | 32 | 30 |
| **/28** | $2^4$ | 16 | 14 |
| **/29** | $2^3$ | 8 | 6 |
| **/30** | $2^2$ | 4 | 2 (Lien point-à-point) |

---

## Cas pratique 1 — Analyser une IP : `192.168.12.160/26`

* **Block size :** $2^{(8-2)} = 2^6 = 64$
* **Blocs du 4ème octet :** `0`, `64`, **`128`**, `192`
* **Localisation :** `.160` se situe dans la tranche `.128` (de `.128` à 
`.191`)

| Élément | Adresse IP |
|:---|:---|
| **Adresse Réseau** | `192.168.12.128` |
| **Premier Hôte** | `192.168.12.129` |
| **Dernier Hôte** | `192.168.12.190` |
| **Broadcast** | `192.168.12.191` |
| **Hôtes disponibles** | 62 |

---

## Cas pratique 2 — Subnetting (Découper un sous-réseau)

**Objectif :** Diviser `10.200.20.0/27` (32 IP) en **4 sous-réseaux égaux**.

* **Calcul :** $32 / 4 = 8$ IP par sous-réseau → Nouveau *Block Size* = $8$ 
($\to$ masque `/29`)

| Subnet # | Adresse Réseau | Plage d'hôtes | Broadcast | Masque |
|:---:|:---|:---|:---|:---:|
| **1** | `10.200.20.0` | `10.200.20.1` - `10.200.20.6` | `10.200.20.7` | 
`/29` |
| **2** | `10.200.20.8` | `10.200.20.9` - `10.200.20.14` | `10.200.20.15` | 
`/29` |
| **3** | `10.200.20.16` | `10.200.20.17` - `10.200.20.22` | `10.200.20.23` 
| `/29` |
| **4** | `10.200.20.24` | `10.200.20.25` - `10.200.20.30` | `10.200.20.31` 
| `/29` |

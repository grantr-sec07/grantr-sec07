# 04-mac-arp.md - MAC & ARP

## Structure d'une adresse MAC
48 bits (6 octets) représentés en hexadécimal - ex: `DE:AD:BE:EF:13:37`

| Partie | Octets | Rôle |
|:---|:---|:---|
| **OUI** | 3 premiers (24 bits) | Identifie le fabricant (attribué par l'IEEE) |
| **NIC** | 3 derniers (24 bits) | Identifiant unique de la carte réseau |

### Bits spécifiques du 1er octet
* **Bit I/G (Individual/Group - Bit 0) :** `0` = Unicast | `1` = Multicast
* **Bit U/L (Universal/Local - Bit 1) :** `0` = Constructeur (Global) | `1` 
= Modifiée / Localement administrée

## Types d'adresses MAC
| Type | Adresse / Condition | Destinataire |
|:---|:---|:---|
| **Unicast** | Bit I/G = 0 | 1 seul hôte spécifique |
| **Multicast** | Bit I/G = 1 (ex: `01:00:5E:...`) | Groupe d'hôtes abonnés 
|
| **Broadcast** | `FF:FF:FF:FF:FF:FF` | Tous les hôtes du segment L2 |

---

## ARP — Address Resolution Protocol
Résout une adresse IP (Couche 3) en adresse MAC (Couche 2) sur le réseau 
local. **Ne traverse jamais un routeur.**

`Requête (Broadcast FF:FF:FF:FF:FF:FF) : "Who has 192.168.1.20? Tell 
192.168.1.10"`  
`Réponse (Unicast) : "192.168.1.20 is at AA:BB:CC:DD:EE:FF"` → *Mise en 
cache ARP*

---

## Vecteurs d'attaques & Contre-mesures

| Attaque | Concept | Impact | Défense recommandée |
|:---|:---|:---|:---|
| **MAC Spoofing** | Modification de l'adresse MAC physique | Bypasser un 
filtre MAC / usurper un équipement | **802.1X** / Authentification forte |
| **MAC Flooding** | Saturation de la table CAM du switch avec de fausses 
MAC | Le switch bascule en mode *Hub* (Fail-Open) et diffuse tout le trafic 
en broadcast | **Port Security** (limite le nombre de MAC par port) |
| **ARP Spoofing / Poisoning** | Envoi de réponses ARP gratuites faussées 
(*Gratuitous ARP*) | Détournement du trafic local / MITM entre la victime et 
la passerelle | **DAI** (*Dynamic ARP Inspection*), ARP Statique |

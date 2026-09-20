# 06-vpn-ipsec.md - VPN & IPsec

## VPN — Principe
Création d'un tunnel chiffré sur Internet entre un client distant et un 
réseau privé. Le client obtient une adresse IP interne et accède aux 
ressources locales comme s'il était sur place.

`Client (Maison) ---> Tunnel Chiffré (Internet) ---> Serveur VPN ---> Réseau 
Interne`

---

## IPsec - Protocoles de sécurité

| Protocole | Chiffrement | Authentification / Intégrité | Usage en production |
|:---|:---|:---|:---|
| **AH** (IP Proto 51) | ❌ Non | ✅ Oui | Rare (ne chiffre pas les données) |
| **ESP** (IP Proto 50) | ✅ Oui | ✅ Oui | Standard (chiffre et authentifie) |

---

## Modes d'opération IPsec

| Mode | Ce qui est chiffré | Cas d'usage |
|:---|:---|:---|
| **Mode Transport** | Charge utile (Data) uniquement | Communication Hôte-à-Hôte sur un même réseau |
| **Mode Tunnel** | Paquet IP entier (En-tête d'origine + Data) | VPN Site-à-Site ou Client-à-Site (Télétravail) |

---

## IKE (Internet Key Exchange) - Négociation des clés
Protocole utilisé pour négocier les algorithmes et établir les clés de 
chiffrement avant le transfert via ESP.

1. **Phase 1 :** Authentification mutuelle des équipements et création d'un 
canal sécurisé (IKE SA).
2. **Phase 2 :** Négociation des clés de chiffrement pour le trafic de 
données ESP (IPsec SA).

*Note : IKEv2 remplace IKEv1 (meilleures performances, reconnexion 
automatique).*

---

## Ports & Protocoles Réseau

| Port / Protocole | Rôle |
|:---|:---|
| **UDP 500** | IKE — Négociation initiale et échange de clés |
| **UDP 4500** | NAT-Traversal (NAT-T) — Encapsulation ESP/UDP pour traverser un routeur/NAT |
| **IP Protocol 50** | ESP — Encapsulating Security Payload (Trafic chiffré) |
| **IP Protocol 51** | AH — Authentication Header |
| **TCP 1723** | PPTP — Point-to-Point Tunneling Protocol (*Obsolète*) |

---

## Protocole obsolète : PPTP
* **Authentification :** MSCHAPv2 + Chiffrement MPPE (basé sur DES).
* **Statut SecOps :** Totalement vulnérable au cassage de clés. Remplacé par 
**OpenVPN**, **WireGuard** ou **IPsec/IKEv2**.

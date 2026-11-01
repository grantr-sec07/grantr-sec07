# Active Directory - Notes SOC / Détection

> Socle Active Directory orienté sécurité. Parcours : HTB Academy - 
*Introduction to
> Active Directory* (16 sections). Même fil rouge que le reste du repo :
> **qui + d'où + quand + quoi** - comprendre pour défendre et détecter.

## Contenu

| Fichier | Sujet |
|---|---|
| [`active-directory-fundamentals.md`](./active-directory-fundamentals.md) | 
Structure, identité, Kerberos, NTLM, groupes, GPO, durcissement || [`ad-attacks-cheatsheet.md`](./ad-attacks-cheatsheet.md) | Les attaques AD + leur détection (Event IDs, outils) |

## L'idée centrale

Active Directory est **« insecure by design »** : conçu pour le partage et 
la
disponibilité, pas pour la sécurité par défaut. Un simple compte de domaine 
peut
énumérer presque tout l'annuaire. La plupart des attaques exploitent des
**mauvaises configurations** (droits excessifs, groupes imbriqués, trusts, 
comptes
de service faibles), pas des failles logicielles.

## Compétences travaillées

- Lire la structure d'un domaine (forêt / domaine / OU / objets)
- Comprendre le flux d'authentification **Kerberos** (TGT, TGS, krbtgt)
- Distinguer les attaques : **Kerberoasting / DCSync / Golden Ticket / 
Pass-the-Hash**
- Repérer les chemins d'escalade via **groupes imbriqués** et **ACL** 
(BloodHound)
- Connaître les mesures de **durcissement** (LAPS, gMSA, account separation)
- Administrer l'AD en **GUI (ADUC/GPMC)** et en **PowerShell** (hands-on)



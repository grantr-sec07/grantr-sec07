# AD - Cheat Sheet Attaques & Détection

Référence des attaques AD vues dans le module, avec l'angle **détection 
SOC**.

## La chaîne type

```
Accès initial (phishing / exploit / creds volés)
   → Discovery : énumération LDAP du domaine (1 compte suffit)
   → Escalade : Kerberoasting / ACL / groupes imbriqués / 
SeImpersonate→SYSTEM
   → Credential access : LSASS dump / DCSync → hash
   → Persistance / contrôle total : Golden Ticket
```

## Les attaques

### Kerberoasting
- **Pré-requis** : un user lambda + un compte de service avec un **SPN**.
- **Mécanisme** : demander un **TGS** → il est chiffré avec le hash du 
compte de
  service → crack offline (Hashcat).
- **Détection** : **Event 4769** en volume, surtout chiffrement **RC4 
(0x17)**.

### AS-REP Roasting
- **Pré-requis** : un compte avec *pre-auth Kerberos désactivée*.
- Récupérer un AS-REP chiffré → crack offline. **Event 4768**.

### Pass-the-Hash (PtH)
- Rejouer un **NT hash** volé (pas besoin du mdp) pour s'authentifier.
- Outils : Mimikatz `sekurlsa::pth`, CrackMapExec `-H`, impacket `-hashes`.
- **Détection** : Event **4624 type 3** en rafale, logons NTLM anormaux.

### LSASS dumping
- Copier la mémoire de `lsass.exe` → extraire hash/tickets.
- `procdump -ma lsass.exe` ou `comsvcs.dll MiniDump` → parse avec 
pypykatz/Mimikatz.
- **Détection** : accès handle à lsass.exe = **alerte EDR majeure** 
(HarfangLab, Defender).

### DCSync
- **Pré-requis** : droits de **réplication** (DA ou DS-Replication).
- Se faire passer pour un DC (via `drsuapi`) → « réplique-moi les hash » → 
NTDS.dit à distance.
- **Détection** : **Event 4662** (accès avec GUID de réplication) depuis un 
host non-DC.

### Golden Ticket
- **Pré-requis** : le **hash de krbtgt** (souvent obtenu par DCSync).
- Forger un TGT valide signé avec krbtgt → impersonate n'importe qui, 
**persistant**.
- Remédiation : changer le mdp krbtgt **deux fois**.

### GPO Abuse
- Droits `GenericWrite`/`WriteDacl`/`WriteOwner` sur un GPO → 
**SharpGPOAbuse** →
  admin local, tâche planifiée, à l'échelle du domaine.

### MachineAccountQuota (RBCD / noPac)
- Par défaut un user peut créer **10 comptes machine** → primitive pour 
RBCD,
  noPac (CVE-2021-42278/42287). Durcir : `MachineAccountQuota = 0`.

## Table des Event IDs (journal Sécurité)

| ID | Signifie | Attaque associée |
|---|---|---|
| 4624 / 4625 | logon réussi / échoué | brute-force, PtH (type 3) |
| 4768 | TGT demandé | AS-REP roasting |
| 4769 | TGS demandé | **Kerberoasting** (RC4 = flag) |
| 4662 | accès objet (réplication) | **DCSync** |
| 4720 | compte créé | persistance |
| 1102 | journal effacé | anti-forensics |

## Outils

| Outil | Usage |
|---|---|
| **BloodHound** | cartographie des chemins d'attaque (groupes, ACL, GPO) |
| **PowerView** | énumération AD en PowerShell |
| **Rubeus** | attaques Kerberos (kerberoast, asreproast, golden) |
| **Mimikatz** | LSASS, PtH, DCSync, golden ticket |
| **CrackMapExec** | PtH, spray, énumération SMB/LDAP |
| **impacket** | secretsdump (DCSync), psexec, etc. |
| **Hashcat** | crack offline des hash/tickets |

## Réflexe défenseur

BloodHound n'est pas qu'un outil d'attaque : un **défenseur** l'utilise pour 
voir
les chemins d'escalade cachés dans son propre domaine et les couper. 
Comprendre
l'attaque = savoir la détecter et la durcir.

# Active Directory - Fondamentaux

Notes orientées sécurité. Chaque brique part du fonctionnement légitime, 
puis
montre l'intérêt défensif / offensif.

---

## 1. Structure

```
Forêt (frontière de sécurité réelle)
 └─ Domaine (unité de gestion, ex. inlanefreight.local)
     └─ OU (conteneurs de rangement → les GPO s'y appliquent)
         └─ Objets (users, computers, groupes, imprimantes...)
```

- **Schéma** = le plan : définit les types d'objets possibles et leurs 
attributs.
- **Trusts** : parent-child (auto, transitif), external, forest. La 
direction de
  l'**accès** est **opposée** à la direction de la **confiance** (A trusts B 
→ B accède à A).
- **Principe clé** : *le domaine n'est pas la frontière de sécurité, la 
**forêt** l'est.*

## 2. Identité & nommage

Un objet se désigne de plusieurs façons :

| Attribut | Rôle |
|---|---|
| **SID** | identifiant de sécurité unique (RID 500 = Administrator) |
| **GUID** (objectGUID) | identifiant unique, **ne change jamais**, même après suppression |
| **DN** | chemin complet (`cn=bjones,ou=IT,dc=inlanefreight,dc=local`) |
| **sAMAccountName** | nom de connexion (≤ 20 car.) |
| **UPN** | `user@domaine` |
| **sIDHistory** | anciens SID (migration) - **abusable** si SID filtering désactivé |

**Security principal** = ce qui peut s'authentifier / détenir des droits →
**users, computers, groups** (ont un SID). Contacts, imprimantes, OU = GUID 
seul.

## 3. Comptes

- **Local** (base SAM) = valable sur **ce host seul**. **Domaine** = tout le 
domaine.
- **SYSTEM** (`NT AUTHORITY\SYSTEM`) = plus haut contexte local. Sur un 
poste joint
  au domaine, SYSTEM ≈ compte machine → **peut énumérer le domaine sans 
voler de mot de passe**.
- **krbtgt** = compte natif caché ; son hash chiffre/signe tous les TGT → 
clé du royaume (Golden Ticket).

## 4. Kerberos (le cœur)

```
1. AS-REQ : user chiffre un timestamp avec SON mdp → KDC (sur le DC)
2. TGT    : KDC renvoie un TGT chiffré avec la clé de krbtgt
3. TGS-REQ: user présente le TGT → demande un TGS pour un service
4. TGS    : chiffré avec le hash du COMPTE DE SERVICE → présenté au service 
→ accès
```

Les deux chiffrements = les deux attaques :
| Chiffré avec | Attaque |
|---|---|
| clé **krbtgt** (le TGT) | **Golden Ticket** |
| hash du **compte de service** (le TGS) | **Kerberoasting** |

- Port **88**. krbtgt est **répliqué sur tous les DC** → n'importe quel DC 
valide un ticket.
- Multi-DC : réplication **multi-maître continue** (pas un backup qui se 
réveille).

## 5. NTLM & hashes

| Type | Où | Attaque |
|---|---|---|
| **NT hash** | SAM / NTDS.dit (stocké) | **Pass-the-Hash** + crack offline |
| **Net-NTLMv1/v2** | réseau (challenge/réponse, jetable) | crack / **relay** - ❌ pas de PtH |
| **DCC2** | cache local (10 derniers logins) | crack ultra-lent (souvent futile) |

> **NT hash = réutilisable → PtH.** **Net-NTLM = one-time → relay ou 
crack.** À ne jamais confondre.

- **LSASS** (`lsass.exe`) = garde en mémoire les hash/tickets des sessions 
ouvertes.
  Le **dumper** (Mimikatz) → voler les creds. Nécessite SYSTEM + 
`SeDebugPrivilege`.

## 6. Groupes

- **Type** : Security (permissions) vs Distribution (mail).
- **Scope** : Domain Local / Global / Universal.
- **Groupes imbriqués** : un user hérite de droits via une chaîne groupe-dans-groupe,
  souvent **non voulus**. → **BloodHound** cartographie ces chemins cachés.
- Privilégiés : Domain Admins (Global), **Enterprise / Schema Admins** 
(Universal, toute la forêt).

## 7. GPO

- Appliqués dans l'ordre **LSDOU** : Local → Site → Domaine → OU, **le 
dernier gagne**
  (OU > Domaine > Site > Local).
- **Enforced** force un GPO d'en haut (inverse la règle) ; **Block 
Inheritance** bloque
  l'héritage ; Enforced bat Block Inheritance.
- Rafraîchissement : **90 min ± 30** (clients), **5 min** (DC) ; `gpupdate 
/force` pour forcer.
- **Abus** : droits `GenericWrite`/`WriteDacl` sur un GPO → 
**SharpGPOAbuse** → admin local,
  tâche planifiée malveillante, à l'échelle du domaine.

## 8. Rôles & services (reconnaître)

- **FSMO** (5 rôles) : surtout **PDC Emulator** (temps → Kerberos) et **RID 
Master** (SID uniques).
- **Global Catalog** : copie partielle de toute la forêt (recherche 
inter-domaine).
- **NTDS.dit** (`C:\Windows\NTDS\`) = la base AD : **tous les hash du 
domaine**.

## 9. Durcissement (côté défense)

| Mesure | Contre quoi |
|---|---|
| **LAPS** | mdp admin local unique par poste → casse le Pass-the-Hash |
| **gMSA** | compte de service, mdp 120 car. auto-roté → inkerberoastable |
| **Account separation** (`user` / `user_adm`) | limite l'impact d'un phishing |
| **DA uniquement sur les DC** | évite les creds DA en mémoire sur un poste 
|
| **MachineAccountQuota = 0** | empêche un user lambda de créer des comptes machine (RBCD/noPac) |
| **Audit & logging** | détecter brute-force, Kerberoasting, énumération |
| **Credential Guard / RunAsPPL** | protège LSASS du dump |

## 10. Administration (hands-on PowerShell)

```powershell
New-ADUser -Name "..." -UserPrincipalName ... -ChangePasswordAtLogon $true 
-Enabled $true -AccountPassword (Read-Host -AsSecureString)
Remove-ADUser -Identity "..."
Unlock-ADAccount -Identity <user>
New-ADOrganizationalUnit -Name "..." -Path "OU=...,DC=...,DC=..."
New-ADGroup -Name "..." -GroupScope Global -GroupCategory Security -Path 
"..."
Add-ADGroupMember -Identity "<groupe>" -Members u1,u2
Copy-GPO -SourceName "..." -TargetName "..."
New-GPLink -Name "..." -Target "OU=...,DC=...,DC=..." -LinkEnabled Yes
Add-Computer -DomainName INLANEFREIGHT.LOCAL -Credential INLANEFREIGHT\<adm> 
-Restart
Get-ADComputer -Identity "<host>" -Properties * | select 
CN,CanonicalName,IPv4Address
```

Trouver le DC depuis un client : `echo %LOGONSERVER%` · `nltest 
/dsgetdc:<domaine>`


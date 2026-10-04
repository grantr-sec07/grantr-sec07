# Windows Fundamentals - Notes SOC

Socle Windows orienté détection. Fil rouge : **qui + d'où + quand + quoi** —
l'outil légitime ne prouve rien, c'est l'usage qui trahit.

## Processus

Filiation normale : `wininit → services.exe → svchost.exe` · `winlogon → explorer.exe → apps`.

Grille pour juger un processus suspect :
- **Chemin** - `svchost.exe` hors de `System32\` = masquerading (T1036)
- **Parent** - `svchost` enfant d'`explorer.exe` = lancement interactif anormal
- **Privilèges** - SYSTEM là où on attend un contexte user
- **Unicité** / **date-signature** - binaire récent, non signé, dans un dossier user

## Persistance - les 5 mécanismes

| Mécanisme | Déclencheur | Privilège | Emplacement | Event ID |
|---|---|---|---|---|
| Processus | manuel | user | RAM | 4688 |
| Tâche planifiée | trigger flexible | user → SYSTEM | `System32\Tasks\` | 4698 |
| Service | boot | SYSTEM | `HKLM\...\Services` | 7045 |
| Run key HKCU | logon user | user | `HKCU\...\Run` | 4657 |
| Run key HKLM | logon (tous) | admin | `HKLM\...\Run` | 4657 |

Escalade type : `processus → tâche → service`. Plus un mécanisme est puissant,
plus il est détectable.

```cmd
sc query <n> / sc qc <n> / sc stop <n> / sc delete <n>
schtasks /query /tn "<n>" /fo LIST /v        :: /fo LIST /v requis pour "Task To Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg delete "HKCU\...\Run" /v <nom> /f        :: viser la valeur, pas la clé
```

Registre : **clés** = dossiers, **valeurs** = fichiers. Ruches : HKLM (machine),
HKCU (user), HKU (tous), HKCR (assoc. fichiers).

## Pare-feu

Entrant vs **sortant** - le malware est déjà dedans, c'est le sortant qui trahit le C2.
- Règle *allow* sortante = discrète → surveiller les **ajouts**
- Pare-feu désactivé = bruyant (5025/4950) → surveiller les **changements d'état**
- Port **4444** = défaut Metasploit

```cmd
netsh advfirewall firewall show rule name=all
netsh advfirewall show allprofiles
netsh advfirewall firewall delete rule name="<n>"      :: admin requis
```

## Journaux d'événements

3 journaux : Application / Système / **Sécurité**. Filtrer par Event ID
(cf. [cheat sheet](./event-ids-cheatsheet.md)).

Anti-forensics : journal **append-only** → impossible de supprimer une ligne,
seulement vider le journal = **Event ID 1102**. L'attaquant ne peut pas effacer
sans laisser la trace de l'effacement. D'où le **log forwarding vers un SIEM** :
copie hors de sa portée. → toujours **corréler plusieurs sources**.

```cmd
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /f:text /c:5
```

## WMI & mouvement latéral

Outil d'admin légitime (local + distant) → **Living off the Land**. Dangereux car :
LOLBin signé Microsoft · **fileless** (exécution mémoire via `-enc`) · mouvement latéral.

```cmd
wmic /node:10.0.0.12 process call create "powershell -enc <base64>"
```
- `/node:` = exécution à distance → **mouvement latéral**
- `-enc` = Base64 (obfuscation) → **décoder avant de conclure** (`base64 -d`)

Post-exploitation, pas une porte d'entrée : il faut déjà un accès + des creds.
Détection : `powershell`/`cmd` enfant de **`WmiPrvSE.exe`** · baseline (qui/d'où/quand) ·
journal `Microsoft-Windows-WMI-Activity/Operational`.

## Méthode d'investigation

1. **Préserver** - hash (`Get-FileHash -Algorithm SHA256`), export config/clé/règle, IOC
2. **Contenir** - isoler (coupe le C2), kill process
3. **Éradiquer** - supprimer la persistance puis le binaire
4. **Chasser** - `netstat -ano`, même hash/IOC sur les autres machines

> On ne mobilise que les gestes liés aux artefacts réellement présents.

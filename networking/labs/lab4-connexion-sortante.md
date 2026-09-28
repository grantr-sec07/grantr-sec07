# Lab 4 : connexion sortante suspecte

## 1. Contexte
Serveur Ubuntu, alerte : une **connexion sortante** inhabituelle. Mission : 
trouver le processus, dire s'il est malveillant, réagir.

## 2. Démarche
- **`ss -tanp`** → relier la connexion à un process. Trouvé : `ESTAB` vers 
**192.168.183.146:4444**, PID **41133** (`beacon`).
- **`ps -o pid,ppid,user,args -p 41133`** → user `fonfon`, commande 
`/tmp/beacon 192.168.183.146 4444`.
- **`ls -l /proc/41133/exe`** → vrai binaire = **`/tmp/beacon`** (un nom 
ment, pas le noyau).
- **`sha256sum`** → l'IOC.
- **PPID** → `sshd → bash → beacon` (lancé depuis un shell SSH).

<img width="731" height="458" alt="image" src="https://github.com/user-attachments/assets/b44db0cc-a925-4e09-acfe-a5133159f53c" />


## 3. Verdict
Suspect : binaire dans **`/tmp`** + nom anodin + sortie **:4444** (C2). 
Trois signaux qui se cumulent.

## 4. Réponse
Isoler (`kill 41133`) → éradiquer (`rm /tmp/beacon`) → bloquer les IOC 
(hash + `:4444`) → approfondir (`bash_history`, date du fichier, hash 
ailleurs).

## 5. Leçon
Partir de l'indice, remonter jusqu'à une preuve irréfutable, conclure sur 
des éléments corroborés. Prouver, pas deviner.

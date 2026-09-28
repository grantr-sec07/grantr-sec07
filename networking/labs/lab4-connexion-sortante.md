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
  

<img width="765" height="302" alt="image" src="https://github.com/user-attachments/assets/1f6bebc4-4cae-4f75-bcf7-3d2a7e02f6a4" />


## 3. Verdict
Suspect : binaire dans **`/tmp`** + nom anodin + sortie **:4444** (C2). 
Trois signaux qui se cumulent.

## 4. Réponse
Isoler (`kill 41133`) → éradiquer (`rm /tmp/beacon`) → bloquer les IOC 
(hash + `:4444`) → approfondir (`bash_history`, date du fichier, hash 
ailleurs).

<img width="326" height="49" alt="image" src="https://github.com/user-attachments/assets/eddfa04b-f9c0-4638-a701-85c69f985478" />


## 5. Leçon
Partir de l'indice, remonter jusqu'à une preuve irréfutable, conclure sur des éléments corroborés. Prouver, pas deviner.

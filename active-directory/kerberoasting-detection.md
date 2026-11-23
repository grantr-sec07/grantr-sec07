# Kerberoasting : la détection (Wazuh, Event 4769)

> Deuxième moitié de mon travail sur le Kerberoasting, le côté défense. La première,
> l'attaque, est dans [`kerberoasting-lab.md`](./kerberoasting-lab.md).
> Ma règle du jeu : une attaque n'est pas finie tant que sa détection n'est pas écrite
> et validée en lab. Ici je prouve que je sais voir l'attaque, pas seulement la lancer.
>
> Les identifiants, mots de passe et noms de domaine montrés viennent d'un lab jetable
> et sont sans valeur.

---

## 1. Objectif

Dans le writeup offensif, j'ai récupéré le mot de passe d'un compte de service en partant
d'un simple compte utilisateur. Ici je change de casquette. Je me mets côté défenseur et je
réponds à une seule question : quand cette attaque passe, qu'est-ce que je dois voir dans mon
SIEM, et comment j'écris une règle qui lève l'alerte sans noyer l'analyste sous les faux
positifs.

Je travaille avec Wazuh, un agent installé sur mon contrôleur de domaine, le tout dans mon
lab AWS.

---

## 2. Où regarder : l'Event 4769, et lui seul

Le Kerberoasting n'exploite aucune faille logicielle. Il détourne un fonctionnement normal de
Kerberos : n'importe quel utilisateur authentifié a le droit de demander un ticket de service.
Résultat, la seule chose que le contrôleur de domaine voit, c'est une demande de ticket
parfaitement légitime : l'**Event 4769** (un TGS a été demandé), dans le journal **Security**
du DC.

Le cassage du hash, lui, se passe hors ligne sur la machine de l'attaquant, sans jamais
reparler au DC. Donc il n'y a rien à détecter au moment du crack. Toute la détection se joue
sur ce 4769, au moment de la demande du ticket.

Pré-requis côté DC : l'audit `Kerberos Service Ticket Operations` doit être en `Success` (il
l'est par défaut sur un contrôleur de domaine). Sans ça, pas de 4769, donc rien à collecter.

---

## 3. La chaîne de collecte

Pour que ce 4769 arrive jusqu'à moi, j'ai monté cette chaîne :

```
Agent Wazuh (sur le DC)  ->  lit le journal Security
      ->  envoie au manager (port 1514)
      ->  le manager décode et compare aux règles
      ->  alerte  ->  indexer  ->  dashboard
```

Deux points que je tenais à faire proprement :

- L'agent parle au manager par l'**IP privée du VPC**, pas par Internet. Rien n'est exposé en
  dehors, et le trafic entre mes deux machines AWS est gratuit.
- L'agent lit le canal `Security` par défaut, donc le 4769 part tout seul vers le manager une
  fois l'agent enrôlé. Pas de config supplémentaire côté agent.

---

## 4. Le signal : RC4 (0x17) perdu au milieu de l'AES (0x12)

C'est le cœur de la détection. Un contrôleur de domaine génère des 4769 en permanence, c'est
du bruit de fond normal. Alerter sur « tout 4769 » serait inutilisable. Il faut un signal qui
sépare l'attaque du trafic légitime.

Ce signal, c'est le **type de chiffrement du ticket**. En rejouant l'attaque avec Wazuh
branché, j'ai comparé les 4769 :

| Qui demande le ticket | Type de chiffrement | Ce que c'est |
|---|---|---|
| Trafic normal (comptes machine, Administrator, krbtgt) | `0x12` | AES256 |
| Mon attaque (compte lambda visant `svc_sql`) | `0x17` | RC4 |

Le Windows Server moderne utilise l'**AES par défaut**. Les outils de Kerberoasting demandent
explicitement du **RC4**, parce qu'un hash RC4 se casse beaucoup plus vite hors ligne. Donc un
4769 en RC4 qui vise un compte de service utilisateur, au milieu d'un océan de 4769 en AES,
**ça détonne**. C'est là-dessus que je construis ma règle.

![Dans le dashboard, l'alerte décodée : eventID 4769, ticketEncryptionType 0x17, service svc_sql](./img/kerberoast-detect-01-event-4769-rc4.png)

---

## 5. La règle Wazuh

Elle vit dans `/var/ossec/etc/rules/local_rules.xml` sur le manager.

```xml
<group name="windows,kerberoasting,">

  <rule id="100100" level="10">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <description>Possible Kerberoasting: TGS 4769 RC4 demande pour le service $(win.eventdata.serviceName)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>

  <rule id="100101" level="0">
    <if_sid>100100</if_sid>
    <field name="win.eventdata.serviceName" type="pcre2">\$$</field>
    <description>Ignore: TGS RC4 vers un compte machine (non pertinent pour le Kerberoasting)</description>
  </rule>

</group>
```

![Ma règle dans local_rules.xml](./img/kerberoast-detect-02-regle-wazuh.png)

Chaque balise, et pourquoi elle est là :

- `id="100100"` : les règles perso vont au-dessus de 100000, en dessous c'est réservé au
  ruleset natif de Wazuh.
- `level="10"` : la sévérité. Au-dessus de 3, Wazuh indexe et affiche l'alerte.
- `<if_sid>60103</if_sid>` : **la règle parente**. 60103 est la règle de base des events du
  **journal Security**. Ma règle ne s'évalue que sur ces events, c'est propre et rapide.
- `<field name="win.system.eventID">^4769$</field>` : on ne garde que l'event 4769. Les `^` et
  `$` ancrent la valeur exacte.
- `<field name="win.eventdata.ticketEncryptionType">^0x17$</field>` : **le filtre qui fait
  tout**, on ne garde que le RC4.
- `<mitre><id>T1558.003</id></mitre>` : je rattache l'alerte à la technique ATT&CK du
  Kerberoasting.

La règle `100101` est une règle enfant (`if_sid 100100`) qui ne se déclenche que si 100100 a
matché **et** que le nom de service finit par `$`, c'est-à-dire un **compte machine**. Comme
elle est plus spécifique et en **niveau 0**, elle écrase l'alerte et étouffe le bruit. Un
compte machine ne se fait pas kerberoaster (son mot de passe est aléatoire et incassable), donc
on l'exclut. C'est le motif d'exclusion propre de Wazuh.

---

## 6. Les pièges que j'ai vraiment rencontrés

Cette règle ne s'est pas mise à tirer du premier coup. Le déboguer m'a appris plus que le
reste, et c'est ce que je veux retenir.

**Le mauvais parent.** J'avais d'abord mis `if_sid 60000`. 60000 est la base de **tous** les
events Windows, alors que 60103 est la base du journal **Security**. Avec le mauvais parent, ma
règle n'entrait jamais dans la bonne branche d'évaluation et ne matchait rien, en silence, sans
erreur. C'est le genre de bug qui fait perdre des heures.

**La constante magique copiée d'un blog.** Le guide officiel de Wazuh pour cette attaque filtre
sur `TicketOptions = 0x40810000`. Sauf que mon vrai event, celui généré par mon outil dans mon
lab, portait `0x40810010`. **Si j'avais copié la règle du blog telle quelle, elle n'aurait
jamais matché mon attaque.** La leçon que je garde : on ne recopie pas une détection en aveugle,
on la valide contre **sa propre télémétrie**. Les valeurs comme `TicketOptions` varient selon
l'outil et la version. C'est pour ça que ma règle finale s'appuie sur le RC4, qui est robuste,
et pas sur `TicketOptions`, qui est fragile.

**Le doublon d'ID.** À force d'essais, je me suis retrouvé avec deux règles portant le même ID
`100100`, dans deux fichiers différents. Wazuh refuse les doublons et ne garde que la première,
ce qui cassait la détection. Un ID de règle doit être unique dans tout le ruleset.

---

## 7. Validation

Je rejoue le Kerberoasting depuis ma Kali, l'alerte tombe côté manager :

```
Rule: 100100 (level 10) -> 'Possible Kerberoasting: TGS 4769 RC4 pour le service svc_sql'
```

![L'alerte générée, vérifiée en ligne de commande sur le manager](./img/kerberoast-detect-03-alerte-validee.png)

La boucle est bouclée, de l'attaque à l'alerte, sur un vrai event capté en direct. Le décodeur
utilisé est bien `windows_eventchannel`, le service ciblé est `svc_sql`, le chiffrement est
`0x17`. Tout concorde avec l'attaque que j'avais menée dans le writeup offensif.

---

## 8. Faux positifs et limites

Une règle honnête se juge aussi sur ce qu'elle laisse passer et sur ce qu'elle déclenche à
tort.

- **RC4 légitime.** De vieux comptes de service ou de vieilles applications peuvent encore
  demander du RC4 pour des raisons de compatibilité. Dans un domaine passé tout en AES, un 4769
  RC4 est quasi toujours suspect. Dans un domaine mixte, il faut maintenir une liste blanche des
  comptes connus pour être légitimement en RC4.
- **Comptes machine.** Déjà exclus par la règle `100101`.
- **Aller plus loin : le volume.** Un cran au-dessus, on peut alerter sur un compte qui demande
  **plusieurs SPN distincts en peu de temps**, qui est le vrai comportement d'un outil qui
  roaste tout le domaine d'un coup. C'est ma piste d'amélioration suivante.

---

## 9. Ce que la détection dit de la défense

Détecter, c'est bien, mais le but final est de rendre l'attaque inutile. La règle RC4 est
doublement utile : elle attrape l'attaque **et** elle révèle les comptes mal configurés, parce
que les deux produisent le même signal, un ticket en RC4.

Les vraies parades, côté durcissement :

- Forcer l'**AES** et abandonner le RC4 sur les comptes de service.
- Des mots de passe longs et aléatoires, idéalement un **gMSA**, dont le mot de passe de 120
  caractères est géré et renouvelé par l'AD lui-même, donc incassable par force brute.

Autrement dit, ma détection RC4 sert aussi de détecteur de dette technique.

---

## 10. Bilan

J'ai fermé la boucle purple sur le Kerberoasting :

```
attaque (TGS en RC4)  ->  télémétrie (Event 4769, 0x17)  ->  règle Wazuh validée  ->  durcissement (AES, gMSA)
```

Technique MITRE ATT&CK : [T1558.003, Kerberoasting](https://attack.mitre.org/techniques/T1558/003/).

---

## Références

- Mon writeup offensif : [`kerberoasting-lab.md`](./kerberoasting-lab.md).
- Wazuh, *How to detect Active Directory attacks with Wazuh*.
- MITRE ATT&CK, [T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003/).

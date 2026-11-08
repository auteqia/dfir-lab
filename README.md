# DFIR LAB

note pour moi même pendant que je construit ce bazar



Pas d'EDR pour les tests et recherche - pas l'objet du lab.

Ni de PPL parce que ça me pose problème pour l'évent id 10 Sysmon pour LSASS



# Comment se servir du repo ?

## 1) Tout refaire

Installer ludus et lancer le template.
Il faudra faire un **attack path**, l'**acquisition** et la **forensic**.

imaginons install.sh qui lance tout


## 2) 

Une fois l'attaque path et l'acquisition faite, les artéfacts forensic sont disponibles dans artifacts. Acquisition avec DFIR-ORC. Bonus questions.md




# Doc

lien vers les trois blogs posts

1) scénario + acquisitions DFIR-ORC
2) disk forensic
3) memory forensic
4) attack path reveal

# Ensuite quelques notes sur le repo

## Pourquoi Debian?
le template debian13 build par ludus sert de routeur, pour que mes autres templates (kali, winsrv et win11) puisse accéder à internet. Logique jusque là. C'est elle qui applique la règle "network" de [[range/range.yaml]]. Fait aussi passer le traffic entre les différents VLAN donc kali <=> windows


## range/range.yaml
description de mes VM, réseau, là où je dis quel rôle ira sur quelle VM, le nom des VM...



## roles/tenenbaum_ad

La configuration complète pour le rôle Active Directory. 

### defaults/main.yaml
On y retrouve la déclaration des users, les OU, les groupes, les mots de passes...

### tasks/main.yaml
ce qu'il y a à exec sur l'AD. Créer les OU. Les Users, Groups... issu de defaults/main.yaml

### meta/main.yaml
nom du role, blabla








## roles/tenenbaum_logging

La télémétrie qui sera appliquée aux machines Windows (Sysmon, powershell logging...)

### defaults/main.yaml
Déclare les politiques de logging (donc quel event ID log, quel cannal Event Viewer...), politique d'audit... Déclare tout ici

### /files/
Contient la configuration Sysmon de [@olafharting](https://github.com/olafhartong/sysmon-modular) pour l'appliquer


### tasks/main.yaml
Ce qui va être executé. Se base sur defaults/main.yaml. Donc, télécharger sysmon, unzip, mettre la config, installer sysmon, changer des clés de registres pour la politique de logging (ex: HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging à DWORD 1)

### meta/main.yaml
nom du role, blabla



# Dans l'ordre (note pour moi même again)

## 1. Déploiement complet 

1h30 lol, une seule fois par contre.

## 2. application des rôles Ansible ad et logging


## 3. rôles workstation


## 4. rôle tooling 

installer winpmem, dfir-orc.. pour plus tard (pas totalement réalise mais ça change rien)


## 5. snapshot de tout ça pour éviter de tout refaire

`ludus testing start`

## 6. attack!! 

mais dry run, tester l'attack path, noter toutes les commandes


## 7. vraie attaque 


## 8. copier toutes les preuves

avec winpmem et dfir orc et les faire sortir pour plus d'analyse



# Lab info

VM	IP
DC01	10.1.10.11
WKS01	10.1.10.21
WKS02	10.1.10.22
kali	10.1.99.1
routeur	10.1.10.254


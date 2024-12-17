# Rapport de Documentation - Projet d'Infection ELF

## Introduction

Ce rapport documente les étapes, les défis rencontrés, et les solutions tentées dans le cadre d’un projet d’infection ELF. L'objectif était de manipuler les en-têtes et segments d’un fichier ELF, d’injecter un shellcode personnalisé, et de modifier le point d’entrée (entry point) pour exécuter le code injecté.

Malgré des progrès significatifs, certains défis techniques n’ont pas pu être totalement surmontés, en particulier ceux liés à la gestion correcte d’un shell dans le contexte du terminal (TTY).

---

## Chronologie du Projet

### **1. Tentative d’Infection à la Main**

#### **Description**
La première étape a consisté à manipuler directement un fichier ELF à l'aide d'outils comme `dd` et un éditeur hexadécimal. L'objectif était de comprendre et de modifier la structure du fichier pour :
- Transformer un segment PT_NOTE en PT_LOAD.
- Injecter un texte ou du code à un offset précis.
- Modifier les permissions d’exécution.

#### **Résultat**
Cette méthode n’a pas été concluante. Malgré les modifications manuelles, plusieurs erreurs ont été rencontrées :
1. Les offsets calculés manuellement étaient imprécis et entraînaient des corruptions dans le fichier ELF.
2. Les modifications des permissions et des types de segments n’étaient pas appliquées de manière cohérente.
3. L’absence d’automatisation rendait le processus laborieux et sujet à des erreurs.

Cette étape, bien qu’infructueuse, a permis de mieux comprendre la structure des fichiers ELF et de clarifier les étapes nécessaires pour réussir l’infection.

---

### **2. Automatisation avec un Script Python**
Après la compréhension manuelle, une tentative a été réalisée pour automatiser le processus avec Python. L’objectif était de modifier les fichiers ELF de manière plus rapide et reproductible.

- **Objectif :** Créer un script capable de :
  - Lire et analyser un fichier ELF.
  - Modifier le type d’un segment PT_NOTE en PT_LOAD.
  - Injecter un shellcode à un emplacement précis.
  - Modifier l’entry point pour pointer vers le shellcode injecté.

- **Avantages du Python :**
  - Une gestion simplifiée des fichiers binaires et des offsets.
  - La possibilité de tester rapidement différentes approches.

- **Résultat :**
  - Le script a permis de valider les concepts, mais l’automatisation a montré ses limites dans les détails liés aux instructions machine et au shellcode.

- **Limitation :** Malgré l’automatisation, la manipulation des instructions assembleur restait difficilement contrôlable avec Python seul, ce qui a motivé le passage à l’assembleur.

---

### **3. Passage à l’Assembleur**

Après l'échec de la méthode manuelle, le projet est passé à une approche en assembleur permettant un contrôle plus précis sur les modifications et manipulations des fichiers ELF.

#### **2.1. Localisation des Segments**
Le premier objectif a été d’identifier les segments PHDR dans le fichier ELF et de localiser un segment PT_NOTE qui pourrait être transformé en PT_LOAD. Cette étape a été réalisée en utilisant la commande readelf et un éditeur hexadécimal afin de :
- Lire les en-têtes ELF et PHDR.
- Identifier les offsets et tailles des segments PHDR.
- Localiser le deuxième segment PT_NOTE à l’offset **0x368** grâce à `readelf` et des calculs complémentaires.

---

#### **2.2. Injection du Shellcode**
L'injection du shellcode a été réalisée en plusieurs étapes :
1. **Transformation du Segment PT_NOTE en PT_LOAD :**
   - Le segment PT_NOTE a été repéré **à la main** à l'offset **0x368**.
   - Les modifications suivantes ont été appliquées :
     - Changement du type de segment (de **4** à **1** pour PT_LOAD).
     - Modification des permissions pour les rendre exécutables (**R E**).
2. **Injection du Shellcode :**
   - Le shellcode a été injecté à l'offset calculé **0x368**.
   - La taille du segment a été agrandie (filesize et memsize) pour éviter les segfaults.

> **Note :** Ma proposition finale n'est **pas dynamique**. J'ai repéré manuellement un segment intéressant que j'ai modifié.

---

#### **2.3. Problèmes Restants et Observations**
Lors des tests, plusieurs segfaults ont été rencontrés. En analysant les erreurs, les points suivants ont été corrigés :
- **Augmentation de la Taille du Segment PT_LOAD :**
  - La taille initiale du segment n'était pas suffisante pour contenir le shellcode. Elle a été augmentée pour couvrir le shellcode injecté.
- **Validation des Offsets et Alignements :**
  - Les offsets ont été ajustés pour respecter les alignements requis par le format ELF.

---

### **3. Problème lié au Shell**

Après avoir injecté un shellcode simple affichant un texte, j'ai tenté d'injecter un shell (exécution de `/bin/sh`). Cependant, cela a entraîné des comportements inattendus :
1. Le shell se lançait correctement, mais un **segfault survenait après environ 3 secondes**.
2. Après être revenu au terminal de base et avoir appuyé sur "Entrée", le shell injecté était toujours actif mais sans contrôle propre du terminal.

#### **Analyse :**
Ce problème est lié à la gestion des processus et du terminal (TTY). Voici ce qui se passe :
1. Le shell se lance mais n'est pas configuré comme leader de groupe de processus.
2. Après quelques secondes, il perd sa connexion au terminal et entraîne un segfault.
3. Lors du retour au terminal de base, le shell injecté est toujours actif en arrière-plan.

---

### **4. Solutions Potentielles**

D'après la documentation consultée, la résolution passe par :
1. **Ajout de `setpgid(0, 0)` :** Configurer le shell comme leader de son propre groupe de processus.
2. **Connexion correcte au terminal :** Gérer explicitement la connexion au TTY.
3. **Attente du Shell :** Le parent du processus shell doit attendre la fin du shell avec `wait4()`.

> **Modifications Clés à Apporter :**
- Configuration correcte des arguments pour `execve` avec un tableau `argv`.
- Gestion dynamique des offsets et tailles des segments.
- Augmentation de la taille du segment PT_LOAD pour éviter les segfaults.

> **Note :** L'application de ces solutions n'ont pas été concluantes et les erreurs persistaient. J'ai donc laissé comme version fonctionnelle celle injectant du texte.

---

## Lancement du Projet

Les fichiers nécessaires sont :
- **hello.c** : Le programme ELF initial.
- **shellcode.asm** : Le programme assembleur responsable de l’infection.

### **Compilation des Fichiers**
> **Note :** Sur la branche **main** les fichiers sont déjà compilés, cette étape peut être passée.

1. Compiler le programme cible :
   ```bash
   gcc -o hello hello.c
   ```

2. Assembler le programme d’infection :
   ```bash
   nasm -f elf64 shellcode.asm -o shellcode.o
   ld shellcode.o -o shellcode
   ```

---

### **Exécution**

1. Lancer le programme d’infection :
   ```bash
   ./shellcode
   ```

2. Exécuter le programme infecté :
   ```bash
   ./hello
   ```

---

## Résultat Actuel

### **Comportement Observé :**
- **Texte Injecté (branche main) :** Le texte "Infected!" et "Hello World!" s'affichent correctement.
- **Shell (branche improved-shellcode) :** Le shell se lance, mais un segfault survient après 3 secondes. Malgré cela, le shell reste actif en arrière-plan et peut être utilisé après un retour au terminal.

### **Problèmes Restants :**
- Gestion incorrecte du terminal.
- Le shell n’est pas configuré comme leader de groupe de processus.
- L'implémentation actuelle manque de dynamisme (les offsets et tailles sont déterminés manuellement).

---

## Conclusion

Ce projet a permis de :
1. Comprendre la structure des fichiers ELF et la manipulation des segments.
2. Injecter un shellcode dans un fichier ELF et modifier son point d’entrée.
3. Identifier des défis techniques liés à la gestion des processus et des terminaux.

# README

## 1) Script de recherche de `.zip`

### Description rapide
- Utilise **gobuster** pour scanner un site et trouver des fichiers/dossiers cachés.
- Cherche spécifiquement des `.zip` (kits de phishing potentiels).
- Télécharge automatiquement les `.zip` trouvés.
- Affiche des infos basiques (type et contenu du ZIP).

### Exécution
1. Assurer que `gobuster`, `wget` et `zipinfo` sont installés.
2. Préparer un fichier texte contenant une liste d’URLs (une URL par ligne).
3. Lancer le script en passant ce fichier en argument :

```bash
./script_recherche_zip.sh urls.txt
```

- Les résultats de `gobuster` seront enregistrés dans des fichiers comme `gobuster_domaine.txt`.
- Les `.zip` trouvés seront téléchargés dans un dossier `zips_domaine/`.
- Le script affichera les métadonnées et le contenu de chaque ZIP téléchargé.

### Personnalisation
- Modifier la variable `wordlist` pour pointer vers votre propre liste de mots (ex. `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`).
- Adapter le nombre de threads (`default_threads`) si nécessaire.
- Changer les codes HTTP exclus avec `-b 403,404,500,468,429` (ou en retirer certains si vous voulez tout garder).

---

## 2) Script d’analyse d’un kit `.zip`

### Description rapide
- Prend un fichier `.zip` (kit phishing) en entrée.
- L’extrait dans un dossier temporaire.
- Parcourt tous les fichiers pour trouver :
  - Fonctions suspectes (ex. `mail(`, `eval(`, `base64_decode(`).
  - Mots-clés dans les fichiers textes (ex. `password`, `account`, `smtp`...).
  - Adresses email, IPs, numéros de téléphone, URLs.
- Génère un rapport (console + `rapport.txt`).

### Exécution
1. Assurer que Python 3 est installé.
2. Lancer :

```bash
./analyse_kit.py mon_kit_phishing.zip
```

- Le contenu du ZIP sera temporairement extrait (dans `/tmp` ou équivalent).
- Les fichiers repérés seront listés dans la console et dans `rapport.txt`.
- Les patterns trouvés sont affichés sous chaque fichier concerné.

### Personnalisation
- Modifier les **regex** dans le script (ex. pour trouver d’autres patterns).
- Adapter les listes `SUSPICIOUS_PATTERNS`, `TEXT_KEYWORDS` pour élargir ou restreindre les recherches.
- Nettoyer le dossier temporaire à la fin du script si on ne veut pas garder l’extraction (désactivé par défaut pour pouvoir consulter les fichiers).

---

## Conseils
- Ces scripts ne font qu’une **analyse statique** basique. Pour détecter des kits plus sophistiqués, il peut être nécessaire d’ajouter d’autres heuristiques (obfuscation, chiffrement, etc.).
- Les résultats doivent être vérifiés manuellement pour confirmer la dangerosité du kit.

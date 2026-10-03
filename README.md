# Calculateur CVSS v4.0 en français

Interface française pour le calcul et la compréhension des évaluations CVSS v4.0. Le moteur `cvss40.js` est conservé tel quel.

## Fonctionnalités

- Calcul CVSS v4.0 en direct.
- Les 32 métriques présentes dans le moteur sont exposées dans l’interface : 11 Base, 1 Threat, 14 Environmental et 6 Supplemental.
- Organisation visuelle par groupes : exploitabilité, impact sur le système vulnérable, impact sur les systèmes subséquents, menace, exigences de sécurité et métriques supplémentaires.
- Explications visibles pour chaque métrique et chaque valeur sélectionnée.
- Justification facultative pour chaque métrique, conservée localement dans le navigateur.
- Vecteur CVSS mis à jour en direct et copiable.
- Nomenclature affichée : CVSS-B, CVSS-BT, CVSS-BE ou CVSS-BTE selon les métriques explicitement renseignées.
- Fonctionnement par vecteur dans l’URL pour pouvoir partager ou recharger une évaluation.
- Interface responsive et accessible au clavier.

## Groupes CVSS

- **Base** : caractéristiques intrinsèques de la vulnérabilité.
- **Threat** : informations évolutives sur la menace, notamment `E` (Exploit Maturity).
- **Environmental** : adaptation à un environnement particulier, avec les exigences de sécurité et les métriques modifiées.
- **Supplemental** : informations contextuelles qui n’entrent pas directement dans le score numérique.

## Moteur

Le fichier `public/cvss40.js` est **identique à la version officielle** de FIRST / Red Hat ([RedHatProductSecurity/cvss-v4-calculator](https://github.com/RedHatProductSecurity/cvss-v4-calculator)) : aucune modification, y compris de la validation des vecteurs. Les libellés de sévérité renvoyés par le moteur (`None`, `Low`, `Medium`, `High`, `Critical`) sont traduits dans `public/app.js`, pas dans le moteur, ce qui permet de le mettre à jour sans conflit.

Au chargement, `app.js` vérifie que `metrics.json` expose exactement les métriques et les valeurs déclarées par `Vector.METRICS` dans `cvss40.js`. En cas d'écart, un message s'affiche et le détail est écrit dans la console du navigateur.

## Tests

```
node test/run.js
```

Sans dépendance. Les tests vérifient :

1. que `cvss40.js` est identique à la version officielle (somme SHA-256 dans `test/cvss40.upstream.sha256`) ;
2. 402 scores de référence (`test/vectors.json`), générés avec la bibliothèque Python `cvss` de Red Hat, une implémentation indépendante du JavaScript : chaque valeur de chaque métrique, plus des vecteurs complets aléatoires ;
3. le rejet des vecteurs invalides (tronqués, valeur inconnue, mauvais ordre, doublon, sans préfixe) ;
4. la couverture des 32 métriques et de leurs valeurs par `metrics.json`, avec une infobulle pour chacune.

Pour mettre à jour le moteur : récupérer le `cvss40.js` officiel, puis régénérer `test/cvss40.upstream.sha256` et relancer les tests.

## Utilisation en local

L'application charge `metrics.json` avec `fetch`, ce qui ne fonctionne pas en ouvrant `index.html` directement (`file://`). Servir le dossier `public/` :

```
cd public && python3 -m http.server 8000
```

puis ouvrir http://localhost:8000. Vue 3.2.45 est hébergé dans `public/vendor/` (licence MIT, voir `LICENSE-vue.txt`) : aucune ressource externe n'est chargée.

## Traductions

Les textes de `metrics.json` suivent le texte anglais officiel (FIRST). Choix de terminologie notables :

- `S` (Safety) est traduit par **Sûreté**, pour le distinguer de la sécurité (Security) ; `MSI` et `MSA` ont aussi la valeur `S` = Sûreté.
- `E:U` (Unreported) est traduit par **Non signalée**.
- `N` vaut **Aucun** pour les impacts de base (`VC`, `VI`, `VA`, `SC`, `SI`, `SA`) et **Négligeable** pour les impacts modifiés `MSC`, `MSI`, `MSA`, comme dans la spécification.
- Quand `E`, `CR`, `IR` ou `AR` valent `X`, le moteur applique le pire cas (`A` pour `E`, `H` pour `CR`/`IR`/`AR`) ; les infobulles le précisent.

## Données locales

Les justifications sont enregistrées dans le `localStorage` du navigateur. Aucune donnée n’est envoyée à un serveur par l’application.

## Licence

Voir `LICENSE`.

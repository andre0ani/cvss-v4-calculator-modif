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

Le fichier `cvss40.js` n’est pas modifié par cette interface. Il contient la logique de calcul CVSS v4.0.

Les valeurs affichées par l’interface sont chargées depuis `metrics.json` et leur ensemble est vérifié pour correspondre aux métriques déclarées par `Vector.METRICS` dans `cvss40.js`.

## Données locales

Les justifications sont enregistrées dans le `localStorage` du navigateur. Aucune donnée n’est envoyée à un serveur par l’application.

## Licence

Voir `LICENSE`.

# Calculateur CVSS 4.0 — Français

Version française et enrichie du calculateur CVSS v4.0.

## Fonctionnalités

- Calcul CVSS v4.0 à partir des métriques du moteur fourni par FIRST.
- Vecteur CVSS conservé dans l'URL.
- Explications visibles pour les métriques et les valeurs sélectionnées.
- Justification libre pour chaque métrique.
- Synthèse textuelle générée à partir des métriques choisies.
- Mode **Rapport de vulnérabilité** séparé du calculateur.
- Reprise automatique du score, du vecteur et des justifications dans le rapport.
- Sauvegarde locale du rapport et des justifications dans le navigateur.
- Copie du vecteur et du rapport Markdown.
- Impression du rapport / génération d'un PDF via la fonction d'impression du navigateur.
- Interface responsive et navigation au clavier.

## Moteur CVSS

Le fichier `cvss40.js` est conservé comme moteur de calcul et n'est pas modifié par cette version de l'interface.

## Utilisation

L'application peut être servie comme site statique. Ouvrir directement `index.html` peut fonctionner selon les restrictions du navigateur, mais un petit serveur HTTP local est recommandé pour permettre le chargement de `metrics.json`.

Par exemple :

```bash
python3 -m http.server 8080
```

Puis ouvrir `http://localhost:8080/`.

## Données locales

Les justifications et le rapport sont enregistrés uniquement dans le `localStorage` du navigateur. Aucune donnée de rapport n'est envoyée par l'application vers un serveur.

## Licence

Voir `LICENSE` pour les informations de licence du projet d'origine.

### CVSS v4.0 metric groups

The interface exposes the four CVSS v4.0 metric groups in canonical order:

1. Base
2. Threat
3. Environmental
4. Supplemental

Threat and Environmental selections are optional and contextual. The displayed score is labelled `CVSS-B`, `CVSS-BT`, `CVSS-BE` or `CVSS-BTE` according to the metric groups explicitly selected. Supplemental metrics provide context and do not modify the numerical CVSS score.


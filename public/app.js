// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

const JUSTIFICATIONS_STORAGE_KEY = "cvss-v4-justifications-french";

// Le moteur cvss40.js reste identique à la version officielle (FIRST / Red Hat) :
// il renvoie les sévérités en anglais, la traduction est faite ici, côté interface.
const SEVERITY_LABELS_FR = {
    None: "Aucun",
    Low: "Bas",
    Medium: "Moyen",
    High: "Haut",
    Critical: "Critique"
};

const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: null,
            vectorInstance: new Vector(),
            cvssInstance: null,
            notice: "",
            noticeTimer: null,
            justifications: {}
        };
    },

    methods: {
        async loadConfigData() {
            try {
                const response = await fetch("./metrics.json", { cache: "no-store" });
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }

                const config = await response.json();
                const issues = this.checkMetricsConsistency(config);
                if (issues.length) {
                    console.error("metrics.json n'est pas cohérent avec cvss40.js :", issues);
                    this.showNotice("Configuration des métriques incohérente avec le moteur CVSS (voir la console).", 15000);
                }

                this.cvssConfigData = config;
                this.loadJustifications();
                this.updateCVSSInstance();
            } catch (error) {
                console.error("Impossible de charger la configuration CVSS :", error);
                this.showNotice("Impossible de charger metrics.json. Servez le dossier public/ via un serveur local (ex. : python3 -m http.server) plutôt que par file://.", 20000);
            }
        },

        // Vérifie que metrics.json expose exactement les métriques et valeurs de Vector.METRICS.
        // Retourne la liste des écarts (vide si tout est cohérent).
        checkMetricsConsistency(config) {
            const issues = [];
            const declared = {};
            Object.values(config).forEach(section => {
                Object.values(section.metric_groups || {}).forEach(group => {
                    Object.values(group).forEach(metric => {
                        if (declared[metric.short]) {
                            issues.push(`Métrique en double dans metrics.json : ${metric.short}`);
                        }
                        declared[metric.short] = Object.values(metric.options).map(option => option.value);
                    });
                });
            });

            Object.values(Vector.METRICS).forEach(category => {
                Object.entries(category).forEach(([key, values]) => {
                    if (!declared[key]) {
                        issues.push(`Métrique absente de metrics.json : ${key}`);
                        return;
                    }
                    const missing = values.filter(value => !declared[key].includes(value));
                    const extra = declared[key].filter(value => !values.includes(value));
                    if (missing.length) issues.push(`${key} : valeurs manquantes (${missing.join(", ")})`);
                    if (extra.length) issues.push(`${key} : valeurs inconnues du moteur (${extra.join(", ")})`);
                });
            });

            Object.keys(declared).forEach(key => {
                if (!(key in Vector.ALL_METRICS)) {
                    issues.push(`Métrique inconnue du moteur : ${key}`);
                }
            });

            return issues;
        },

        groupDescription(groupName, sectionName) {
            const descriptions = {
                "Métriques d’exploitabilité": "Décrivent les conditions nécessaires pour exploiter la vulnérabilité.",
                "Métriques d’impact sur le système vulnérable": "Décrivent les conséquences directes de l'exploitation sur le système vulnérable.",
                "Métriques d’impact sur les systèmes subséquents": "Décrivent les conséquences sur d'autres systèmes ou composants affectés après l'exploitation.",
                "Métriques de menace": "Décrivent l'état actuel de la menace, notamment la maturité de l'exploitation.",
                "Exigences de sécurité": "Indiquent l'importance relative de la confidentialité, de l'intégrité et de la disponibilité dans cet environnement.",
                "Métriques Supplémentaires": "Ajoutent du contexte à l'évaluation sans modifier directement le score numérique."
            };

            if (descriptions[groupName]) {
                return descriptions[groupName];
            }

            if (sectionName === "Environnemental (Contexte de l’environnement)") {
                return "Ces métriques permettent d'adapter l'évaluation à un environnement particulier.";
            }

            return "";
        },

        sectionDescription(sectionName, fill) {
            if (sectionName === "Métriques de Base") {
                return "Caractéristiques intrinsèques de la vulnérabilité, indépendantes d'un environnement particulier.";
            }

            if (sectionName === "Métriques de menace") {
                return "Informations susceptibles d'évoluer dans le temps, notamment selon les éléments connus sur l'exploitation.";
            }

            if (sectionName === "Environnemental (Contexte de l’environnement)") {
                return "Adapte l'évaluation à un environnement précis, à ses contrôles et à ses exigences de sécurité. Ces métriques sont facultatives.";
            }

            if (sectionName === "Métriques Supplémentaires") {
                return "Informations complémentaires destinées à apporter du contexte. Elles ne modifient pas directement le score CVSS.";
            }

            return fill === "consumer" ? "Informations propres à l'environnement évalué." : "";
        },

        displayGroupName(groupName, sectionName) {
            if (sectionName === "Environnemental (Contexte de l’environnement)") {
                const modified = {
                    "Métriques d’exploitabilité": "Métriques d’exploitabilité modifiées",
                    "Métriques d’impact sur le système vulnérable": "Métriques d’impact sur le système vulnérable modifiées",
                    "Métriques d’impact sur les systèmes subséquents": "Métriques d’impact sur les systèmes subséquents modifiées"
                };
                return modified[groupName] || groupName;
            }
            return groupName;
        },

        sectionMetricCount(metricTypeData) {
            return Object.values(metricTypeData.metric_groups || {}).reduce((total, group) => total + Object.keys(group).length, 0);
        },

        sectionClass(sectionName) {
            const classes = {
                "Métriques de Base": "section-base",
                "Métriques de menace": "section-threat",
                "Environnemental (Contexte de l’environnement)": "section-environmental",
                "Métriques Supplémentaires": "section-supplemental"
            };
            return classes[sectionName] || "";
        },

        groupClass(groupName) {
            const classes = {
                "Métriques d’exploitabilité": "group-exploitability",
                "Métriques d’impact sur le système vulnérable": "group-vulnerable-impact",
                "Métriques d’impact sur les systèmes subséquents": "group-subsequent-impact",
                "Métriques de menace": "group-threat",
                "Exigences de sécurité": "group-requirements"
            };
            return classes[groupName] || "group-default";
        },

        optionClass(value) {
            const classes = {
                X: "value-undefined",
                N: "value-none",
                L: "value-low",
                M: "value-medium",
                H: "value-high",
                P: "value-present",
                A: "value-active",
                S: "value-special",
                C: "value-context",
                D: "value-context",
                Y: "value-yes",
                U: "value-unproven",
                I: "value-inconclusive",
                Clear: "value-clear",
                Green: "value-green",
                Amber: "value-amber",
                Red: "value-red"
            };
            return classes[value] || "value-default";
        },

        selectedOption(metricData) {
            const value = this.vectorInstance.metrics[metricData.short];
            const entry = Object.entries(metricData.options).find(([, optionData]) => optionData.value === value);

            if (!entry) {
                return {
                    value: "X",
                    label: "Non défini",
                    description: "La métrique n'est pas définie."
                };
            }

            return {
                value: entry[1].value,
                label: entry[0],
                description: entry[1].tooltip || "Aucune description disponible."
            };
        },

        joinFrench(items) {
            if (!items || items.length === 0) return "";
            if (items.length === 1) return items[0];
            if (items.length === 2) return `${items[0]} et ${items[1]}`;
            return `${items.slice(0, -1).join(", ")} et ${items[items.length - 1]}`;
        },

        onButton(metric, value) {
            this.vectorInstance.updateMetric(metric, value);
            this.updateCVSSInstance();
            window.location.hash = this.vector;
        },

        loadVector(vector) {
            const value = String(vector || "").trim();
            if (!value) {
                this.resetSelected();
                window.location.hash = "";
                return;
            }

            try {
                const nextVector = new Vector(value);
                this.vectorInstance = nextVector;
                this.updateCVSSInstance();
                window.location.hash = this.vector;
                this.showNotice("Vecteur CVSS chargé.");
            } catch (error) {
                console.error("Vecteur CVSS invalide :", error);
                this.showNotice("Le vecteur CVSS fourni n'est pas valide.");
            }
        },

        setButtonsToVector(vector) {
            if (!vector) {
                this.resetSelected();
                this.updateCVSSInstance();
                return;
            }

            try {
                this.vectorInstance = new Vector(vector);
                this.updateCVSSInstance();
            } catch (error) {
                console.error("Erreur lors du chargement du vecteur :", error);
                this.showNotice("Le vecteur présent dans l'URL n'est pas valide.");
                window.location.hash = "";
                this.resetSelected();
                this.updateCVSSInstance();
            }
        },

        updateCVSSInstance() {
            try {
                this.cvssInstance = new CVSS40(this.vectorInstance);
            } catch (error) {
                console.error("Erreur de calcul CVSS :", error);
                this.cvssInstance = null;
            }
        },

        resetSelected() {
            this.vectorInstance = new Vector();
        },

        resetAll() {
            this.resetSelected();
            this.justifications = {};
            this.updateCVSSInstance();
            window.location.hash = "";
            this.saveJustifications();
            this.showNotice("Évaluation réinitialisée.");
        },

        copyText(text, successMessage) {
            const fallback = () => {
                const textarea = document.createElement("textarea");
                textarea.value = text;
                textarea.style.position = "fixed";
                textarea.style.opacity = "0";
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand("copy");
                textarea.remove();
            };

            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).catch(fallback).finally(() => this.showNotice(successMessage));
            } else {
                fallback();
                this.showNotice(successMessage);
            }
        },

        copyVector() {
            this.copyText(this.vector, "Vecteur CVSS copié dans le presse-papiers.");
        },

        loadJustifications() {
            try {
                const stored = localStorage.getItem(JUSTIFICATIONS_STORAGE_KEY);
                this.justifications = stored ? JSON.parse(stored) : {};
            } catch (error) {
                console.warn("Impossible de charger les justifications locales :", error);
                this.justifications = {};
            }
        },

        saveJustifications() {
            try {
                localStorage.setItem(JUSTIFICATIONS_STORAGE_KEY, JSON.stringify(this.justifications));
            } catch (error) {
                console.warn("Impossible de sauvegarder les justifications :", error);
            }
        },

        showNotice(message, duration = 3000) {
            this.notice = message;
            clearTimeout(this.noticeTimer);
            this.noticeTimer = setTimeout(() => {
                this.notice = "";
            }, duration);
        },

        scrollToSection(id) {
            const element = document.getElementById(id);
            if (element) {
                element.scrollIntoView({ behavior: "smooth", block: "start" });
            }
        },

        severityClass() {
            const classes = {
                Bas: "severity-low",
                Moyen: "severity-medium",
                Haut: "severity-high",
                Critique: "severity-critical",
                Aucun: "severity-none"
            };
            return classes[this.severityRating] || "severity-none";
        }
    },

    computed: {
        vector() {
            return this.vectorInstance.raw;
        },

        score() {
            return this.cvssInstance ? this.cvssInstance.score : 0;
        },

        severityRating() {
            if (!this.cvssInstance) return SEVERITY_LABELS_FR.None;
            return SEVERITY_LABELS_FR[this.cvssInstance.severity] || this.cvssInstance.severity;
        },

        nomenclature() {
            return this.vectorInstance ? this.vectorInstance.nomenclature : "CVSS-B";
        },

        definedMetricCount() {
            return Object.values(this.vectorInstance.metrics).filter(value => value !== "X").length;
        },

        generatedSummary() {
            if (!this.cvssInstance) {
                return "Le score n'est pas disponible.";
            }

            const metrics = this.vectorInstance.metrics;
            const parts = [];
            const access = {
                N: "à distance via le réseau",
                A: "depuis un réseau adjacent",
                L: "localement",
                P: "avec un accès physique"
            };

            if (access[metrics.AV]) {
                parts.push(`exploitable ${access[metrics.AV]}`);
            }

            const privileges = {
                N: "sans privilèges préalables",
                L: "avec de faibles privilèges",
                H: "avec des privilèges élevés"
            };
            if (privileges[metrics.PR]) {
                parts.push(privileges[metrics.PR]);
            }

            const interaction = {
                N: "sans interaction utilisateur",
                P: "avec une interaction utilisateur passive",
                A: "avec une interaction utilisateur active"
            };
            if (interaction[metrics.UI]) {
                parts.push(interaction[metrics.UI]);
            }

            const impacts = [];
            const impactLabels = [
                ["VC", "confidentialité"],
                ["VI", "intégrité"],
                ["VA", "disponibilité"]
            ];

            impactLabels.forEach(([metric, label]) => {
                if (metrics[metric] === "H") impacts.push(`un impact élevé sur la ${label}`);
                if (metrics[metric] === "L") impacts.push(`un impact faible sur la ${label}`);
            });

            let summary = parts.length
                ? `La vulnérabilité est ${parts.join(", ")}.`
                : "Les conditions d'exploitation sont décrites par les métriques sélectionnées.";

            if (impacts.length) {
                summary += ` L'impact comprend ${this.joinFrench(impacts)}.`;
            }

            if (this.nomenclature !== "CVSS-B") {
                summary += ` L'évaluation utilise ${this.nomenclature}.`;
            }

            return summary;
        },

    },

    watch: {
        justifications: {
            deep: true,
            handler() {
                this.saveJustifications();
            }
        }
    },

    async beforeMount() {
        await this.loadConfigData();
        this.setButtonsToVector(window.location.hash.slice(1));
    },

    mounted() {
        window.addEventListener("hashchange", () => {
            const hash = window.location.hash.slice(1);
            if (hash && hash !== this.vector) {
                this.setButtonsToVector(hash);
            }
        });
    }
});

app.mount("#app");

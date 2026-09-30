// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

const REPORT_STORAGE_KEY = "cvss-v4-report-french";
const JUSTIFICATIONS_STORAGE_KEY = "cvss-v4-justifications-french";

const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: null,
            currentView: "calculator",
            macroVector: null,
            vectorInstance: new Vector(),
            cvssInstance: null,
            notice: "",
            noticeTimer: null,
            justifications: {},
            report: this.defaultReport()
        };
    },
    methods: {
        defaultReport() {
            return {
                title: "",
                reference: "",
                target: "",
                date: new Date().toISOString().slice(0, 10),
                author: "",
                description: "",
                impactConfidentiality: "",
                impactIntegrity: "",
                impactAvailability: "",
                evidence: "",
                remediation: "",
                references: ""
            };
        },

        async loadConfigData() {
            try {
                const response = await fetch("./metrics.json", { cache: "no-store" });
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                this.cvssConfigData = await response.json();
                this.loadLocalData();
                this.resetSelected();
                this.updateCVSSInstance();
            } catch (error) {
                console.error("Failed to load configuration data:", error);
                this.showNotice("Impossible de charger la configuration CVSS.");
            }
        },

        fillDescription(fill) {
            if (fill === "consumer") {
                return "À renseigner selon le contexte spécifique de l'environnement évalué.";
            }
            return "Métriques utilisées pour l'évaluation de la vulnérabilité.";
        },

        optionClass(value) {
            const optionClasses = {
                H: "option-high",
                L: "option-low",
                N: "option-none",
                P: "option-present",
                A: "option-active",
                X: "option-undefined"
            };
            return optionClasses[value] || "";
        },

        getSeverityClass(severityRating) {
            const severityClasses = {
                Bas: "severity-low",
                Moyen: "severity-medium",
                Haut: "severity-high",
                Critique: "severity-critical",
                Aucun: "severity-none"
            };
            return severityClasses[severityRating] || "severity-none";
        },

        selectedOption(metricData) {
            const value = this.vectorInstance.metrics[metricData.short];
            const entry = Object.entries(metricData.options).find(([, optionData]) => optionData.value === value);
            if (!entry) {
                return { value: "X", label: "Non défini", description: "La métrique n'est pas définie." };
            }
            return {
                value: entry[1].value,
                label: entry[0],
                description: entry[1].tooltip || "Aucune description disponible."
            };
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
            window.location.hash = this.vector;
        },

        onButton(metric, value) {
            this.vectorInstance.updateMetric(metric, value);
            window.location.hash = this.vector;
            this.updateCVSSInstance();
        },

        setButtonsToVector(vector) {
            if (!vector) {
                this.updateCVSSInstance();
                return;
            }
            try {
                this.vectorInstance.updateMetricsFromVectorString(vector);
                this.updateCVSSInstance();
            } catch (error) {
                console.error("Error updating vector:", error.message);
                this.showNotice("Le vecteur présent dans l'URL n'est pas valide.");
            }
        },

        updateCVSSInstance() {
            this.cvssInstance = new CVSS40(this.vectorInstance);
            this.macroVector = this.vectorInstance.equivalentClasses;
        },

        resetSelected() {
            this.vectorInstance = new Vector();
        },

        resetAll() {
            this.resetSelected();
            this.justifications = {};
            this.report = this.defaultReport();
            this.updateCVSSInstance();
            window.location.hash = "";
            this.saveJustifications();
            this.saveReport();
            this.showNotice("Calcul et rapport réinitialisés.");
        },

        setView(view) {
            this.currentView = view;
            window.scrollTo({ top: 0, behavior: "smooth" });
        },

        showNotice(message) {
            this.notice = message;
            clearTimeout(this.noticeTimer);
            this.noticeTimer = setTimeout(() => {
                this.notice = "";
            }, 3000);
        },

        loadLocalData() {
            try {
                const storedJustifications = localStorage.getItem(JUSTIFICATIONS_STORAGE_KEY);
                if (storedJustifications) {
                    this.justifications = JSON.parse(storedJustifications);
                }

                const storedReport = localStorage.getItem(REPORT_STORAGE_KEY);
                if (storedReport) {
                    this.report = { ...this.defaultReport(), ...JSON.parse(storedReport) };
                }
            } catch (error) {
                console.warn("Unable to load local data:", error);
            }
        },

        saveJustifications() {
            try {
                localStorage.setItem(JUSTIFICATIONS_STORAGE_KEY, JSON.stringify(this.justifications));
            } catch (error) {
                console.warn("Unable to save justifications:", error);
            }
        },

        saveReport() {
            try {
                localStorage.setItem(REPORT_STORAGE_KEY, JSON.stringify(this.report));
            } catch (error) {
                console.warn("Unable to save report:", error);
            }
        },

        printReport() {
            this.currentView = "report";
            this.$nextTick(() => window.print());
        },

        copyMarkdown() {
            this.copyText(this.markdownReport, "Rapport Markdown copié dans le presse-papiers.");
        },

        formatDate(date) {
            if (!date) return "";
            const parsed = new Date(`${date}T00:00:00`);
            return new Intl.DateTimeFormat("fr-FR").format(parsed);
        },

        valueLabel(metricData) {
            return this.selectedOption(metricData).label;
        },

    },
    computed: {
        vector() {
            return this.vectorInstance.raw;
        },

        score() {
            return this.cvssInstance ? this.cvssInstance.score : 0;
        },

        severityRating() {
            return this.cvssInstance ? this.cvssInstance.severity : "Aucun";
        },

        generatedSummary() {
            if (!this.cvssInstance || !this.cvssConfigData) {
                return "Sélectionnez les métriques pour générer une synthèse.";
            }

            const metrics = this.vectorInstance.metrics;
            const parts = [];

            const access = [];
            if (metrics.AV === "N") access.push("à distance via le réseau");
            if (metrics.AV === "A") access.push("depuis un réseau adjacent");
            if (metrics.AV === "L") access.push("localement");
            if (metrics.AV === "P") access.push("avec un accès physique");

            if (access.length) parts.push(`Cette vulnérabilité est exploitable ${access[0]}`);

            if (metrics.PR === "N") parts.push("sans privilèges préalables");
            if (metrics.PR === "L") parts.push("avec de faibles privilèges");
            if (metrics.PR === "H") parts.push("avec des privilèges élevés");

            if (metrics.UI === "N") parts.push("sans interaction utilisateur");
            if (metrics.UI === "P") parts.push("avec une interaction utilisateur passive");
            if (metrics.UI === "A") parts.push("avec une interaction utilisateur active");

            const impacts = [];
            if (["H", "L"].includes(metrics.VC)) impacts.push(`un impact ${metrics.VC === "H" ? "élevé" : "faible"} sur la confidentialité`);
            if (["H", "L"].includes(metrics.VI)) impacts.push(`un impact ${metrics.VI === "H" ? "élevé" : "faible"} sur l'intégrité`);
            if (["H", "L"].includes(metrics.VA)) impacts.push(`un impact ${metrics.VA === "H" ? "élevé" : "faible"} sur la disponibilité`);

            let summary = parts.length ? parts.join(", ") + "." : "Les conditions d'exploitation sont décrites par les métriques sélectionnées.";
            if (impacts.length) {
                summary += ` L'impact comprend ${this.joinFrench(impacts)}.`;
            }
            return summary;
        },

        reportMetrics() {
            if (!this.cvssConfigData) return [];
            const result = [];
            Object.values(this.cvssConfigData).forEach(typeData => {
                Object.values(typeData.metric_groups || {}).forEach(groupData => {
                    Object.entries(groupData).forEach(([name, metricData]) => {
                        const selected = this.selectedOption(metricData);
                        result.push({
                            short: metricData.short,
                            name,
                            valueLabel: selected.label,
                            value: selected.value,
                            justification: this.justifications[metricData.short] || ""
                        });
                    });
                });
            });
            return result;
        },

        markdownReport() {
            const r = this.report;
            const lines = [
                `# ${r.title || "Vulnérabilité sans titre"}`,
                "",
                r.reference ? `**Référence :** ${r.reference}` : "",
                r.target ? `**Cible :** ${r.target}` : "",
                r.date ? `**Date :** ${this.formatDate(r.date)}` : "",
                r.author ? `**Auteur :** ${r.author}` : "",
                "",
                "## Description",
                "",
                r.description || "_Non renseignée._",
                "",
                "## Évaluation CVSS v4.0",
                "",
                `**Score : ${this.score} — ${this.severityRating}**`,
                "",
                `\`${this.vector}\``,
                "",
                this.generatedSummary,
                "",
                "## Justification des métriques",
                "",
                ...this.reportMetrics.map(metric => `- **${metric.short} — ${metric.name} : ${metric.valueLabel}** — ${metric.justification || "Aucune justification renseignée."}`),
                "",
                "## Impact",
                "",
                `### Confidentialité\n${r.impactConfidentiality || "_Non renseigné._"}`,
                "",
                `### Intégrité\n${r.impactIntegrity || "_Non renseigné._"}`,
                "",
                `### Disponibilité\n${r.impactAvailability || "_Non renseigné._"}`,
                "",
                "## Preuve / PoC",
                "",
                r.evidence || "_Non renseignée._",
                "",
                "## Recommandation / remédiation",
                "",
                r.remediation || "_Non renseignée._",
                "",
                "## Références",
                "",
                r.references || "_Aucune._",
                ""
            ];
            return lines.filter((line, index, array) => !(line === "" && array[index - 1] === "" )).join("\n");
        },

    },

    watch: {
        report: {
            deep: true,
            handler() {
                this.saveReport();
            }
        }
    },

    async beforeMount() {
        await this.loadConfigData();
        this.setButtonsToVector(window.location.hash.slice(1));
    },

    mounted() {
        window.addEventListener("hashchange", () => {
            this.setButtonsToVector(window.location.hash.slice(1));
        });
    }
});

app.mount("#app");

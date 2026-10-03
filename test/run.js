// Tests sans dépendance : node test/run.js
// Vérifie que le calculateur reste fidèle au moteur officiel cvss40.js (FIRST / Red Hat)
// et que metrics.json couvre toutes les métriques du moteur.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const root = path.join(__dirname, "..", "public");
const { CVSS40, Vector } = require(path.join(root, "cvss40.js"));
let failures = 0;
const ok = (cond, msg) => { if (!cond) { failures++; console.log("  ECHEC :", msg); } };
const section = title => console.log("\n" + title);

// 1. Le moteur est identique à la version officielle
section("1. Intégrité du moteur cvss40.js");
const expectedHash = fs.readFileSync(path.join(__dirname, "cvss40.upstream.sha256"), "utf8").split(/\s+/)[0];
const actualHash = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "cvss40.js"))).digest("hex");
ok(actualHash === expectedHash, `cvss40.js a été modifié (sha256 ${actualHash} ≠ ${expectedHash}). ` +
   "Si la mise à jour depuis FIRST/Red Hat est volontaire, régénérez test/cvss40.upstream.sha256.");
console.log(actualHash === expectedHash ? "  OK : identique à la version de référence" : "");

// 2. Scores de référence (générés par la bibliothèque Python indépendante)
section("2. Scores de référence");
const ref = JSON.parse(fs.readFileSync(path.join(__dirname, "vectors.json"), "utf8")).vectors;
let scoreErrors = 0;
for (const { vector, score, severity } of ref) {
  const r = new CVSS40(vector);
  if (r.score !== score || r.severity !== severity) {
    scoreErrors++;
    if (scoreErrors <= 5) console.log(`  écart : ${vector} -> ${r.score}/${r.severity}, attendu ${score}/${severity}`);
  }
}
ok(scoreErrors === 0, `${scoreErrors} vecteur(s) en écart sur ${ref.length}`);
console.log(`  ${ref.length - scoreErrors}/${ref.length} vecteurs conformes`);

// 3. Validation stricte des vecteurs
section("3. Validation des vecteurs");
const realError = console.error; console.error = () => {};
const valid = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
const invalids = {
  "vecteur tronqué": "CVSS:4.0/AV:N/AC:L",
  "préfixe seul": "CVSS:4.0",
  "valeur inconnue": valid.replace("AV:N", "AV:Z"),
  "ordre incorrect": "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  "métrique en double": valid.replace("AV:N/", "AV:N/AV:N/"),
  "sans préfixe": valid.replace("CVSS:4.0/", ""),
};
ok(new Vector().validateStringVector(valid) === true, "le vecteur valide est rejeté");
for (const [label, v] of Object.entries(invalids)) {
  let rejected;
  try { rejected = new Vector().validateStringVector(v) === false; } catch { rejected = true; }
  ok(rejected, `vecteur invalide accepté : ${label}`);
}
console.error = realError;

// 4. metrics.json couvre exactement les métriques du moteur
section("4. Cohérence metrics.json / Vector.METRICS");
const config = JSON.parse(fs.readFileSync(path.join(root, "metrics.json"), "utf8"));
const declared = {};
(function walk(o) {
  if (o && typeof o === "object") {
    if (o.short && o.options) {
      ok(!declared[o.short], `métrique en double : ${o.short}`);
      declared[o.short] = Object.values(o.options).map(x => x.value);
      Object.entries(o.options).forEach(([label, x]) => ok(x.tooltip && x.tooltip.length > 0, `infobulle vide : ${o.short}:${x.value}`));
      ok(o.tooltip && o.tooltip.length > 0, `infobulle vide : ${o.short}`);
    }
    Object.keys(o).forEach(k => { if (k !== "options") walk(o[k]); });
  }
})(config);
let count = 0;
for (const category of Object.values(Vector.METRICS)) {
  for (const [key, values] of Object.entries(category)) {
    count++;
    ok(declared[key], `métrique absente de metrics.json : ${key}`);
    if (!declared[key]) continue;
    ok(values.every(v => declared[key].includes(v)) && declared[key].every(v => values.includes(v)),
       `${key} : valeurs différentes (moteur ${values} / json ${declared[key]})`);
  }
}
ok(Object.keys(declared).length === count, `metrics.json déclare ${Object.keys(declared).length} métriques, le moteur ${count}`);
console.log(`  ${count} métriques du moteur couvertes`);

console.log(failures ? `\n${failures} échec(s)` : "\nTous les tests passent.");
process.exit(failures ? 1 : 0);

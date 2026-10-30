# 🧹 Rebuild & Troubleshooting GregorForge

Ce document aide à diagnostiquer les erreurs Docker sans supposer qu'elles
sont temporaires ni supprimer les données locales.

---

## 1. Erreurs Docker fréquentes

Exemple typique :

```bash
failed to solve: error getting credentials
````

Ou :

```bash
load metadata for docker.io/library/debian
````

Ces erreurs peuvent provenir du réseau/DNS, du registre, de WSL, d'une
dépendance ou d'une instruction de build. Elles ne sont pas nécessairement
temporaires ni externes au projet. Lire l'étape qui échoue et les logs avant de
relancer une opération.

### Solution simple

Relancer la commande :

```bash
docker compose build
````

ou :

```bash
docker compose up -d
```

---

## 2. Pourquoi Docker peut échouer

Causes fréquentes :

* timeout réseau,
* problème DNS,
* cache Docker corrompu,
* WSL instable (Windows).

Vérifier les erreurs exactes dans la sortie du build et dans les logs ; ne pas
conclure qu'elles sont sans rapport avec le projet avant cette vérification.

---

## 3. Attention : scripts de réinitialisation

`recreate_clean.sh`, mentionné dans une version antérieure de ce guide, n'existe
pas dans ce checkout. Les scripts actuellement présents (`install.sh` et
`install-dev.sh`) sont destructifs : ils arrêtent Compose, suppriment volumes et
répertoires de données/configuration, purgent le cache Docker, puis recréent la
stack. Ne les lancez pas sans sauvegarde et revue des suppressions.

Voir le détail vérifié dans [`LOCAL_SETUP.md`](LOCAL_SETUP.md).

---

## 4. Héritage de configuration

Même après un rebuild :

* les fichiers de configuration peuvent être **réinjectés**,
* les agents peuvent être **recopiés automatiquement**,
* la logique de seed ne s’exécute **qu’une seule fois**.

---

## 5. Quand NE PAS rebuild

Ne rebuild **pas** si :

* vous modifiez uniquement un agent Markdown,
* vous changez un prompt,
* vous modifiez un workflow Python dans un volume monté.

👉 Ces changements sont pris en compte **à chaud**.

---

## 6. Debug avancé

### Vérifier les conteneurs

```bash
docker ps
```

### Logs OpenCode

```bash
docker logs opencode
```

### Logs GregorForge Toolbox

```bash
docker logs gregorforge
```

---

## 7. Résumé rapide

* Erreur Docker ≠ problème GregorForge
* Relancer suffit souvent
* les scripts d'installation actuels suppriment des données ; les éviter sans sauvegarde
* Volumes = modification sans rebuild

---

➡️ Pour comprendre l’architecture :
voir [`ARCHITECTURE_REVIEW.md`](ARCHITECTURE_REVIEW.md) et
[`full.md`](full.md).

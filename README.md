# DevSec Lab — collecte et règle R1

Application de test → fichier JSONL → collecteur persistant → API FastAPI → base SQL → tableau de bord.

Ce prototype collecte les événements et détecte les échecs répétés via R1. Le ML, la corrélation multi-scénarios, le LLM, GitHub et les actions restent à réaliser.

## Démarrer sous Windows

Prérequis : Python 3.10 ou plus. Pour PostgreSQL, Docker Desktop doit fonctionner en mode conteneurs Linux.

```powershell
cd <dossier-agent-devsec>
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Le script crée l’environnement Python, installe les dépendances, initialise les secrets locaux, démarre PostgreSQL via Compose puis les quatre processus Python. Les identifiants du tableau de bord sont générés dans **ACCESS_LOCAL.md**. Ils ne doivent pas être publiés.

Pour un démarrage local sans Docker :

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1 -Database sqlite
```

PostgreSQL est la cible du projet ; SQLite est un mode de développement et de tests. Chaque mode possède ses propres événements. Le collecteur déjà acquitté ne renvoie pas les anciens logs lors d’un changement de base : produire une nouvelle tentative de connexion pour vérifier le nouveau mode.

## Essayer le parcours

1. Ouvrir **http://127.0.0.1:8010** et se connecter avec les identifiants de `ACCESS_LOCAL.md`.
2. Ouvrir **http://127.0.0.1:8011**.
3. Tester `etudiant` avec un mot de passe incorrect : un événement `auth.failure` est écrit.
4. Tester `etudiant` / `demo-lab` : un événement `auth.success` est écrit.
5. Attendre environ 2 à 5 secondes : consulter les événements, filtrer par résultat et cliquer sur « Voir le log ».

L’application observée simule une authentification. Elle ne fournit pas encore de session et de routes applicatives protégées. Ses comptes sont fictifs. Le tableau de bord, lui, possède une vraie session locale de consultation (expiration 8 h, cookie HttpOnly, contrôle d’origine, limitation des tentatives).

## Commandes de développement

```powershell
.\.venv\Scripts\python.exe -m devsec.setup
.\.venv\Scripts\python.exe -m devsec.run --database postgres
.\.venv\Scripts\python.exe -m pytest -q
```

Ctrl+C arrête les processus Python du lanceur. La base Docker reste démarrée pour conserver son service ; `docker compose stop` l’arrête sans supprimer les données. Ne pas utiliser `down -v` si vous voulez conserver les événements.

Si le prototype a été lancé en arrière-plan : `powershell -ExecutionPolicy Bypass -File .\stop.ps1` arrête uniquement ses processus Python enregistrés, après vérification de leur exécutable et de leur commande.

Les journaux techniques sont dans `.local/api.log`, `.local/demo.log` et `.local/collector.log`. Ils n’affichent pas les clés d’accès. Le fichier observé est `.local/logs/demo.jsonl`. Le collecteur conserve curseurs, lots en attente et motifs de quarantaine dans `.local/collector.db`.

## Garanties vérifiées par les tests

- Contrainte unique `(source, event_id)` : livraison répétée sans événement supplémentaire.
- Un même ID avec un contenu différent est rejeté explicitement.
- Enregistrement du lot en base avant acquittement ; réponse par événement.
- Spool et curseur atomiques, reprise après indisponibilité de l’API ou perte de sa réponse.
- Ligne incomplète attendue ; JSON invalide, ligne trop longue ou événement rejeté mis en quarantaine sans conserver sa valeur brute.
- Rotation par renommage avec archives conservées à côté du fichier ; troncature détectée si la taille devient inférieure au curseur.
- Horodatages avec fuseau, contrôle des champs, source autorisée, taille de lot bornée.
- Mot de passe absent des événements ; utilisateur pseudonymisé ; HTML affiché via échappement et `textContent`.
- Tableau de bord et endpoints de lecture protégés, collecteur authentifié par clé distincte.

Limite de rotation : une troncature suivie d’une réécriture plus longue entre deux lectures peut être invisible. Utiliser la rotation par renommage, conserver les archives jusqu’à lecture et ne pas supprimer les fichiers encore en attente. La collecte n’offre pas de garantie face à une suppression externe des sources non lues.

## Organisation

```text
devsec/
  api.py          # ingestion, session et lecture des événements
  collector.py    # fichier → spool SQLite → API
  demo.py         # application observée, émission de logs
  database.py     # schéma SQLAlchemy partagé SQLite/PostgreSQL
  schemas.py      # contrat strict du premier type d’événement
  config.py       # configuration et secrets locaux
  run.py          # lanceur des trois processus
  templates/      # connexion, tableau de bord, démo
  static/         # CSS et JavaScript sans dépendance externe
tests/            # scénarios d’intégration et de reprise
compose.yaml      # PostgreSQL 16, volume persistant
```

Les deux applications sont réunies dans ce dossier pour faciliter ce premier incrément ; la séparation en deux dépôts prévue par le dossier sera faite lors de l’intégration CI/CD. Le schéma initial est créé automatiquement de manière non destructive. Les migrations Alembic sont à ajouter avant sa première évolution.

## Périmètre local et prochaines étapes

Les services n’écoutent que sur `127.0.0.1`. Ce lancement n’est pas un déploiement public : HTTPS, gestion multi-utilisateur, rôles opérateur/mainteneur, rétention 30 jours et durcissement du déploiement restent à réaliser.

L’API n’accepte pour l’instant que `auth.failure` et `auth.success` de `demo-auth`, volontairement. L’extension aux sources système, accès HTTP et pare-feu nécessitera des schémas et parseurs spécifiques, pas un assouplissement silencieux du contrat.

Prochain incrément proposé : ajouter les sources et règles suivantes après validation de R1.


## Règle R1 — échecs de connexion répétés

- Au moins **5 échecs dans une fenêtre glissante de 5 minutes**, bornes incluses.
- Clé : compte pseudonymisé + IP + service + environnement.
- Calcul sur l’heure des événements UTC, et non leur heure de réception.
- Gravité moyenne, état initial nouveau. Une connexion réussie n’annule pas les échecs précédents.
- Un épisode continue tant qu’il n’y a pas plus de 5 minutes sans échec pour cette clé. Les fenêtres qualifiantes enrichissent le même incident ; une pause supérieure à 5 minutes permet un nouvel épisode.
- Les preuves sont l’union des fenêtres ayant atteint le seuil ; `peak_count` est le maximum d’échecs sur UNE fenêtre de cinq minutes, pas le total sur toute la durée de l’incident.
- Les événements tardifs sont réévalués ; deux épisodes reliés tardivement sont fusionnés avec conservation de l’identifiant le plus ancien correspondant. Les événements sources ne sont jamais supprimés par R1.

Le worker `python -m devsec.rules` est lancé automatiquement par `devsec.run`. Il analyse toutes les données toutes les 2 secondes : ce choix simple convient au laboratoire, pas à une grande volumétrie. Un seul worker R1 doit tourner en SQLite ; PostgreSQL utilise un verrou transactionnel de règle.

### Tester visuellement

1. Lancer avec `start.ps1 -Database sqlite`, ouvrir le tableau de bord et l’application de test.
2. Choisir un nouveau nom d’utilisateur fictif pour isoler l’essai.
3. Faire quatre tentatives avec un mot de passe incorrect : aucun incident pour ce compte.
4. Faire la cinquième dans les cinq minutes : attendre environ 2 à 7 secondes.
5. Dans « Incidents R1 », cliquer sur « Voir les preuves » : cinq logs justifient l’incident.
6. Une sixième tentative enrichit l’incident au lieu de le dupliquer.

La liste `/incidents` est paginée et `/incidents/{id}` expose les preuves ; ces routes exigent une session de consultation. Aucun blocage ni aucune autre action n’est exécuté.

### Évolution additive du stockage

Deux nouvelles tables, `incidents` et `incident_evidence`, sont créées au lancement avec clés et contraintes. Les tables existantes et les logs sont conservés. Le lanceur initialise le schéma avant de démarrer les processus pour éviter une course au premier lancement. Aucun champ existant n’est modifié ; une future modification de colonnes nécessitera une migration versionnée. Faire une sauvegarde avant cette future évolution.

`rules.log` contient les erreurs du moteur ; un incident visible ne prouve pas que le worker tourne actuellement. La supervision explicite du worker sera ajoutée au suivi d’exploitation.

## Simulation R3

Le simulateur émet une délégation pour un compte fictif. Elle autorise le redémarrage
de demo-worker pendant une heure. Choisir X seule, X puis Y exécutée, ou X puis Y refusée.
Y représente la modification des paramètres. Seule son exécution hors périmètre
déclenche un incident. Aucun service ni droit système réel ne change.

Le moteur rapproche compte, service, environnement, opération et ressource au moment
de l’action. L’échéance est exclue. Une nouvelle délégation remplace la précédente
pour le compte sur ce service. Une rétrogradation révoque la délégation.
Les anciens événements de rôle et de maintenance gardent leur interprétation historique.

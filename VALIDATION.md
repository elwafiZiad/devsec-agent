# Validation du premier incrément

Date : 13 novembre 2026.

## Résultats observés

- **13 tests automatisés réussis** (`python -m pytest -q`).
- Parcours réel dans Microsoft Edge en mode automatisé : connexion au tableau de bord, tentative refusée puis acceptée dans l’application, collecte effective, apparition des deux événements, filtre et détail de preuve.
- Aucune erreur JavaScript constatée pendant ce parcours.
- Affichage vérifié à 1440 px et 390 px ; pas de débordement horizontal de la page mobile (le tableau possède son propre défilement).
- Redémarrage du collecteur et de la base persistante couvert par les tests ; doublons après perte d’acquittement couverts.
- Authentification, contrôle d’origine, limitation des tentatives, taille de lot, schéma, données Unicode, lignes invalides, rotation et panne API couverts.

## Environnement réellement testé

Windows, Python 3.10, API FastAPI, collecteur Python, base **SQLite persistante**. Les tests de navigateur utilisent Edge local ; Playwright n’est pas nécessaire au fonctionnement de l’application.

PostgreSQL reste la cible du projet. Le pilote et la configuration Docker Compose sont fournis, mais **l’exécution PostgreSQL n’a pas pu être validée** : Docker Desktop a été lancé, puis les requêtes au moteur ont expiré. Le mode SQLite permet de poursuivre le premier parcours sans modifier la cible de conception.

## Ce qui n’est pas encore réalisé

ML, corrélation, LLM, GitHub, actions, logs système/pare-feu, rôles multiples, migrations d’évolution, rétention automatique et déploiement HTTPS. Le tableau de bord affiche maintenant les événements et les incidents R1.


## Ajout R1 — 13 novembre 2026

20 tests automatisés réussis (13 existants + 7 nouveaux). Nouveaux cas : seuil 4/5, enrichissement sans doublon, frontière exacte 300 secondes, séparation compte/IP/service/environnement, succès exclus, arrivée désordonnée, redémarrage, nouvelle séquence après silence et fusion tardive. Les endpoints incidents nécessitent une authentification.

L’exécution PostgreSQL reste non validée ; les essais ont lieu en SQLite. L’algorithme reparcourt l’historique et n’a pas encore été évalué à forte charge.

Essai réel dans Edge réussi : quatre échecs sans incident, cinquième échec déclencheur, cinq preuves, consultation du détail et affichage mobile sans débordement. Les services de test isolés ont été arrêtés après vérification.


## Validation Docker et PostgreSQL — 18 novembre 2026

Docker Desktop 4.83.0 et son moteur Linux 29.6.2 répondent via le contexte desktop-linux. WSL2 et la distribution docker-desktop sont actifs. L’indisponibilité observée le 13 novembre ne se reproduit plus au diagnostic du 18 novembre.

L’image postgres:16-alpine a été téléchargée et le conteneur devsec-lab-db-1 créé avec son volume persistant. Le contrôle de santé est positif. Les dépendances Python du projet du Bureau, dont psycopg 3.2.13, sont installées dans .venv.

Le parcours réel dans Edge a réussi sur PostgreSQL : quatre échecs sans incident pour un compte de test neuf, puis le cinquième échec déclenche R1 avec cinq preuves consultables. L’API confirme explicitement le moteur postgresql. Les cinq événements et l’incident persistent après redémarrage du conteneur.

Les données SQLite antérieures restent dans leur fichier local. Les données PostgreSQL ont leur propre volume et les données de recette ont été produites séparément. Le spool acquitté ne rejoue pas automatiquement l’ancien historique lors d’un changement de base.

Commande normale de lancement depuis le dossier du projet : powershell -ExecutionPolicy Bypass -File .\start.ps1

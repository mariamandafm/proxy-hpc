# proxy-hpc

## Estrutura

| Diretório | O que é |
|---|---|
| `SATOSA/` | Proxy de identidade SAML/OIDC. A configuração fica em `SATOSA/configs/`. |
| `cuidapp/` | API que gera e guarda o identificador persistente do usuário (CUID). |
| `satosa-oidc-frontend/` | Frontend OIDC do Core AAI usado pelo SATOSA. |
| `satosa-micro_services/` | Plugins do Core AAI para o SATOSA (inclui o plugin CUID). |
| `pysaml2/` | Fork GÉANT da biblioteca SAML usada pelo SATOSA. |
| `idpy-oidc/` | Fork GÉANT da biblioteca OIDC usada pelo `satosa-oidc-frontend`. |
| `deploy/` | Arquivos do Docker: imagem e script de inicialização do SATOSA, configuração do nginx e criação do banco do frontend OIDC. |

## Como rodar

```sh
cp .env.example .env   # preencha os valores
docker compose up -d --build
```

Parar:

```sh
docker compose down
```

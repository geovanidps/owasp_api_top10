# Scanner OWASP API Security Top 10 (2023) — com testes de bypass

Ferramenta didática em Python 3 para avaliar APIs REST contra as **10 categorias
do OWASP API Security Top 10 (2023)**, executando **tentativas reais de bypass**
(não apenas sugerindo "pode ser vulnerável"), com menu interativo e modo CLI.

## ⚠️ AVISO LEGAL — LEIA ANTES DE USAR

Esta ferramenta executa ataques ativos: bypass de autenticação (JWT `alg=none`),
IDOR/BOLA, escalonamento de privilégio, mass assignment, força bruta de login,
flood de requisições, SSRF, fuzzing de versões de API, etc.

**Use somente em:**
- Sistemas de sua propriedade;
- Ambientes de laboratório/CTF;
- Alvos com autorização explícita e por escrito (contrato de pentest).

Testar sistemas de terceiros sem autorização pode configurar crime (no Brasil,
Lei 12.737/2012 e dispositivos do Código Penal, além de legislações
equivalentes em outros países). O script exige que o operador digite
`CONFIRMO` (ou use `--yes` conscientemente) antes de qualquer teste.

## Os 10 itens cobertos (OWASP API Security Top 10:2023)

| Código | Categoria | Técnica de bypass aplicada |
|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | Enumeração de IDs adjacentes + acesso cruzado com token de outro usuário |
| API2 | Broken Authentication | Acesso sem token, forjar JWT com `alg=none`, força bruta de login sem rate limit |
| API3 | Broken Object Property Level Authorization | Exposição de campos sensíveis na resposta + mass assignment (`isAdmin`, `role`) |
| API4 | Unrestricted Resource Consumption | Flood concorrente de requisições + paginação sem limite |
| API5 | Broken Function Level Authorization | Acesso a endpoint admin com usuário comum + troca de verbo HTTP (GET→DELETE) |
| API6 | Unrestricted Access to Sensitive Business Flows | Repetição automatizada de fluxo de negócio sem CAPTCHA/anti-automação |
| API7 | Server Side Request Forgery (SSRF) | Indução do servidor a buscar metadados de nuvem / localhost / arquivos locais |
| API8 | Security Misconfiguration | Headers de segurança ausentes, CORS `*`, stack trace exposto, paths sensíveis |
| API9 | Improper Inventory Management | Fuzzing de versões (`v1`, `v2`, `beta`, `legacy`...) e docs expostas |
| API10 | Unsafe Consumption of APIs | Payloads malformados em endpoints de integração/webhook |

Cada teste retorna um status: `VULNERÁVEL` (bypass confirmado), `PROTEGIDO`,
`INCONCLUSIVO` (indício, requer revisão manual) ou `IGNORADO` (faltou
configuração para esse teste).

## Instalação

```bash
pip install requests colorama   # colorama é opcional, só para cores no terminal
# em ambientes com pip --break-system-packages, se necessário:
pip install --break-system-packages requests colorama
```

Compatível com Python 3.8+. Sem outras dependências.

## Como usar

**Agora basta informar a URL da API** — o scanner descobre os endpoints
sozinho (via especificação OpenAPI/Swagger, se publicada, ou sondando padrões
de rota REST comuns) e **gera o `config.json` automaticamente** por trás dos
panos. Você só precisa escrever um `config.json` manualmente se quiser
refinar/completar o que foi descoberto, ou se a API tiver rotas muito fora do
padrão.

### 1) Modo interativo (recomendado para começar)

```bash
python3 owasp_api_top10.py
```

Isso abre o menu:

```
1) ⭐ Gerar configuração a partir de uma URL (recomendado — só a URL)
2) Ver os 10 itens do OWASP API Security Top 10
3) Carregar configuração já existente (config.json)
4) Gerar config.json de exemplo em branco (edição manual)
5) Executar TODOS os testes (bypass completo)
6) Executar um teste específico (API1-API10)
7) Exportar último relatório (JSON/HTML)
8) Ajuda / termo de uso autorizado
0) Sair
```

Fluxo recomendado (mais rápido):
1. Opção **1** → informe apenas a URL da sua API de teste/laboratório, e
   (opcionalmente) token(s) de autenticação ou usuário+senha para login
   automático. O scanner descobre os endpoints, monta e **salva o
   `config.json` sozinho**, já mostrando o que encontrou.
2. Opção **5** (todos os testes) ou **6** (um teste específico).
3. Confirme digitando `CONFIRMO` quando solicitado.
4. Opção **7** → exporte o relatório em JSON ou HTML.

Se a descoberta automática não encontrar tudo (APIs com padrões de rota
incomuns, por exemplo), use a opção **3** para carregar o `config.json` que
foi salvo pela opção 1, edite-o manualmente completando/corrigindo os
endpoints, e carregue-o de novo.

### 2) Modo linha de comando (CLI), útil para automação/CI

```bash
# Modo automático: só a URL (gera e salva o config.json sozinho)
python3 owasp_api_top10.py --url http://127.0.0.1:5000 --all --yes --output relatorio.html

# Com token(s) de autenticação (recomendado: um token por usuário, para
# detectar IDOR/BOLA cruzado entre contas)
python3 owasp_api_top10.py --url http://127.0.0.1:5000 \
    --token TOKEN_USUARIO_1 --secondary-token TOKEN_USUARIO_2 \
    --all --yes --output relatorio.html

# Com login automático (se um endpoint de login for encontrado)
python3 owasp_api_top10.py --url http://127.0.0.1:5000 \
    --username admin --password minhasenha --all --yes

# Rodar testes específicos a partir da URL
python3 owasp_api_top10.py --url http://127.0.0.1:5000 --test API1 API5 API8

# Modo manual: usar um config.json já existente/editado
python3 owasp_api_top10.py --config config.json --all --yes --output relatorio.html
```

O `config.json` gerado a partir da URL é sempre salvo em disco (por padrão
`config.json`, ou o caminho passado em `--save-config`), para você conferir
exatamente o que foi testado e reutilizar/editar depois com `--config`.

Flags disponíveis: `--url`, `--token`, `--secondary-token`, `--username`,
`--password`, `--save-config`, `--no-verify-ssl`, `--config`, `--all`,
`--test API1 API2 ...`, `--output`, `--yes` (confirma autorização
automaticamente), `--init-config`, `--menu`.

## Configuração (`config.json`) — gerada automaticamente ou manual

Você normalmente **não precisa escrever este arquivo à mão**: ele é gerado
pela opção 1 do menu (ou `--url` na CLI) a partir da URL informada. Ele fica
salvo em disco para consulta/edição. Campos principais:

```json
{
  "base_url": "http://127.0.0.1:5000",
  "primary_token": "TOKEN_DO_USUARIO_1",
  "secondary_token": "TOKEN_DO_USUARIO_2",
  "auth_header": "Authorization",
  "auth_scheme": "Bearer",
  "login_endpoint": "/api/login",
  "login_body_template": {"username": "admin", "password": "{password}"},
  "rate_limit_requests": 40,
  "documented_version": "v1",
  "endpoints": [
    {
      "path": "/api/v1/users/{id}",
      "method": "GET",
      "id_param": "id",
      "sample_id": "2",
      "alt_id": "1",
      "auth_required": true,
      "sensitive_fields": ["email"],
      "privileged": false,
      "url_param_for_ssrf": null
    }
  ]
}
```

### Como funciona a descoberta automática (por trás da opção "só a URL")

1. **OpenAPI/Swagger**: tenta localizar uma especificação publicada em
   caminhos comuns (`/openapi.json`, `/swagger.json`, `/v2/api-docs`, etc.).
   Se encontrar, importa todas as rotas e verbos documentados diretamente.
2. **Heurística de rotas comuns**: se não houver especificação publicada,
   sonda combinações de prefixo (`/api/v1`, `/api/v2`, `/api`, `""`) com
   recursos REST comuns (`users`, `products`, `orders`, `admin`, `webhooks`,
   etc.), tanto na forma de listagem quanto de detalhe (`/recurso/1`).
   Qualquer resposta diferente de 404 é considerada uma rota existente
   (mesmo que protegida por autenticação).
3. **Login**: sonda caminhos de login comuns (`/api/login`, `/auth/login`,
   etc.) para habilitar o teste de força bruta (API2). Se você informar
   usuário e senha, tenta logar automaticamente e extrair um token da
   resposta.
4. Tudo isso é montado em um `ScanConfig` e **salvo em `config.json`**.

- **`primary_token` / `secondary_token`**: tokens de dois usuários distintos
  (permitem testar IDOR cruzado no API1). Se o token "parecer" um JWT
  (`header.payload.assinatura`), o teste de bypass `alg=none` é acionado
  automaticamente no API2.
- **`sample_id` / `alt_id`**: IDs de objetos usados para tentar IDOR.
- **`privileged: true`**: marca endpoints administrativos (testados no API5).
- **`url_param_for_ssrf`**: nome do parâmetro que aceita uma URL (testado no
  API7). Na descoberta automática esse nome é apenas um palpite inicial — na
  hora do teste, o scanner também envia simultaneamente os nomes mais comuns
  (`url`, `target_url`, `webhook_url`, `callback_url`, `uri`), então não é
  necessário acertar o nome exato de primeira.
- **`sensitive_fields`**: campos que você sabe que DEVEM aparecer na resposta
  (evita falso-positivo no API3).
- **`login_endpoint` / `login_body_template`**: usados para o teste de força
  bruta sem rate limit (API2). Use `{password}` como placeholder.

## Testando o scanner localmente (API de laboratório incluída)

O arquivo `vulnerable_mock_api.py` sobe uma API Flask **intencionalmente
vulnerável** (todos os 10 itens falham de propósito), para você validar o
scanner e aprender a interpretar o relatório sem tocar em sistemas reais:

```bash
pip install flask
python3 vulnerable_mock_api.py &

# Modo recomendado: apenas a URL + tokens de dois usuários de teste
python3 owasp_api_top10.py --url http://127.0.0.1:5000 \
    --token token-user1 --secondary-token token-user2 \
    --all --yes --output relatorio.html

# Alternativa: usar o config_test.json manual incluído (mesmo alvo)
python3 owasp_api_top10.py --config config_test.json --all --yes --output relatorio.html
```

Rodar o comando acima deve reportar ~19 vulnerabilidades confirmadas (com
tokens) — isso é esperado, é um alvo propositalmente quebrado para fins de
ensino. `config_test.json` é mantido no pacote como exemplo de configuração
manual equivalente à que a descoberta automática geraria.

## Limitações conhecidas (sempre complemente com revisão manual)

- **API6** (fluxos de negócio) e **API10** (consumo de APIs de terceiros) são
  difíceis de confirmar 100% automaticamente, pois dependem de regra de
  negócio específica da aplicação — o scanner reporta `INCONCLUSIVO` com
  indícios, não um veredito definitivo.
- O teste de SSRF (API7) não acessa redes externas reais por padrão além dos
  alvos internos clássicos (metadados de nuvem, localhost); em ambientes reais,
  avalie também DNS rebinding e redirecionamentos.
- Resultados `PROTEGIDO` significam "não foi possível confirmar o bypass com
  os dados fornecidos", não uma certificação de segurança absoluta.

## Estrutura dos arquivos entregues

- `owasp_api_top10.py` — scanner principal (menu interativo + CLI).
- `vulnerable_mock_api.py` — API de laboratório para testes/validação.
- `config_test.json` — configuração de exemplo já apontando para o mock.
- `README.md` — este guia.

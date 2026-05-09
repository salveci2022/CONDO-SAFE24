# 🏢 CONDO-SAFE24 — Sistema SaaS de Segurança para Condomínios

**Versão 2.0 PRO** | Desenvolvido por SpyNet Tecnologia Forense  
CNPJ: 64.000.808/0001-51 | spynetintelligence@proton.me

---

## 📋 Descrição

Sistema SaaS multiempresa de segurança para condomínios, portarias e empresas. Permite que moradores acionem um botão de pânico com GPS em tempo real, notificando imediatamente a central de monitoramento.

## 🚀 Funcionalidades

- **Botão de Pânico** com GPS em tempo real (via browser)
- **Central de Monitoramento** com alertas ao vivo + sirene
- **Painel Administrativo** para gestão de clientes e chaves
- **Multiempresa** — isolamento por chave de cliente
- **Relatório PDF** profissional com histórico de alertas
- **PWA** — instala no celular sem app store
- **Rate Limiting** — proteção contra abuso e brute-force
- **Logs de auditoria** de todas as ações críticas

## 🏗️ Stack Técnica

| Componente | Tecnologia |
|-----------|-----------|
| Backend | Python 3.11 + Flask 2.3 |
| Servidor | Gunicorn (Render.com) |
| PDF | ReportLab |
| Autenticação | Sessões Flask + hash seguro |
| Armazenamento | Memória + JSON (data/keys.json) |
| PWA | Manifest + Service Worker |

## ⚙️ Setup Local

```bash
# 1. Clone e entre no diretório
git clone https://github.com/seu-usuario/CONDO-SAFE24.git
cd CONDO-SAFE24

# 2. Crie o ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# 3. Instale dependências
pip install -r requirements.txt

# 4. Configure variáveis de ambiente
cp .env.example .env
# Edite o .env com suas senhas e chave secreta

# 5. Execute
flask run
# ou
python app.py
```

## 🌐 Deploy no Render

1. Faça push do repositório para o GitHub
2. No Render, crie um **Web Service**
3. Configure as variáveis de ambiente (ver `.env.example`):
   - `SECRET_KEY` — chave secreta aleatória (mínimo 32 caracteres)
   - `CENTRAL_PASSWORD` — senha da central de monitoramento
   - `ADMIN_PASSWORD` — senha do painel administrativo
   - `APP_TZ` — fuso horário (padrão: `America/Sao_Paulo`)
   - `FLASK_ENV` — `production`
4. Build Command: `pip install -r requirements.txt`
5. Start Command: `gunicorn -c gunicorn.conf.py app:app`

## 🔑 Estrutura de Acessos

| Rota | Quem Acessa | Proteção |
|------|------------|---------|
| `/` | Público | Nenhuma |
| `/sos?key=CONDO-XXXX` | Morador (com chave) | Chave de cliente |
| `/central` | Porteiro / Central | Senha `CENTRAL_PASSWORD` |
| `/painel_publico` | Central | Senha `CENTRAL_PASSWORD` |
| `/admin` | Administrador | Senha `ADMIN_PASSWORD` |
| `/report.pdf` | Central / Admin | Sessão autenticada |

## 🛡️ Segurança Implementada (v2.0)

- ✅ `debug=False` em produção
- ✅ `SECRET_KEY` via variável de ambiente
- ✅ Rate limiting em todas as APIs críticas
- ✅ Proteção brute-force no login (bloqueio após 10 tentativas)
- ✅ Sanitização de inputs contra XSS/injection
- ✅ Headers de segurança (X-Content-Type, X-Frame-Options, etc.)
- ✅ Sessões seguras com HttpOnly e SameSite
- ✅ Logs de auditoria para login e alertas
- ✅ Rotas de admin protegidas com decorators

## 📁 Estrutura do Projeto

```
CONDO-SAFE24/
├── app.py                  # Backend Flask (rotas, APIs, lógica)
├── gunicorn.conf.py        # Configuração do servidor de produção
├── requirements.txt        # Dependências Python
├── runtime.txt             # Versão do Python (Render)
├── .env.example            # Template de variáveis de ambiente
├── .gitignore
├── data/
│   └── keys.json           # Chaves de clientes (auto-criado)
├── static/
│   ├── manifest.json       # PWA manifest
│   ├── siren.wav.mp3       # Áudio de alarme
│   └── icons/              # Ícones PWA
└── templates/
    ├── home.html           # Landing page
    ├── sos.html            # Botão de pânico do morador
    ├── central.html        # Painel de monitoramento
    ├── painel_publico.html # Painel público de alertas
    ├── admin.html          # Gestão de clientes
    ├── login_central.html  # Login da central
    ├── login_admin.html    # Login do admin
    └── forbidden.html      # Página de acesso negado
```

## 💰 Modelo Comercial SaaS

| Plano | Preço/mês | Condomínios | Usuários |
|-------|-----------|------------|---------|
| Starter | R$ 97 | 1 | 50 moradores |
| Profissional | R$ 197 | 5 | 200 moradores |
| Enterprise | R$ 497 | Ilimitado | Ilimitado |

## 📞 Suporte

- **Email**: spynetintelligence@proton.me
- **WhatsApp**: Disponível no site
- **GitHub**: @salveci2022

---

*CONDO-SAFE24 © 2024-2025 SpyNet Tecnologia Forense — Todos os direitos reservados*

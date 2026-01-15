# 🛡️ CONDO-SAFE24 Security

Sistema de segurança escolar com monitoramento em tempo real, controle de acesso e alertas automatizados.

## 📋 Funcionalidades

- ✅ **Monitoramento em Tempo Real**
- ✅ **Controle de Acesso**
- ✅ **Sistema de Alertas**
- ✅ **Relatórios Automatizados**
- ✅ **Interface Web**

## 🚀 Começando

### Pré-requisitos
- Python 3.8+
- Dependências listadas em `requirements.txt`

### Instalação
```bash
git clone https://github.com/salvec2022/spynet-security.git
cd spynet-security
pip install -r requirements.txt

## 🔒 Segurança Nível Alto (chave por cliente)

O painel **/sos** só funciona com chave válida.

### Como gerar chaves
1) Entre no **Admin** (recomendado configurar `ADMIN_PASSWORD`)
2) Use a seção **"Gestão de Chaves"** para gerar e ativar/desativar chaves.
3) Envie ao cliente apenas o link:

`https://SEU-DOMINIO.onrender.com/sos?key=COND-XXXXXXXXXXXX`

### Produção (recomendado): salvar chaves em variável de ambiente
Você pode definir `CONDO_KEYS_JSON` no Render para manter as chaves mesmo após deploy:

Exemplo:
```json
{
  "COND-ABC123": {"name": "Condomínio Alfa", "active": true},
  "COND-XYZ999": {"name": "Condomínio Beta", "active": true}
}
```

Variáveis úteis:
- `SECRET_KEY` (obrigatório em produção)
- `CENTRAL_PASSWORD` (senha da Central)
- `ADMIN_PASSWORD` (senha do Admin)
- `CONDO_KEYS_JSON` (chaves por cliente)

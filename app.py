from flask import Flask, render_template, send_file, jsonify, request, redirect, url_for, session
import os
import datetime
import logging
from io import BytesIO
from zoneinfo import ZoneInfo

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'condo-safe24-secret')  # necessário para login da central

TZ = ZoneInfo(os.environ.get('APP_TZ', 'America/Sao_Paulo'))

# Configuração
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
logging.basicConfig(level=logging.INFO)

# Armazenamento em memória
alertas = []
sistema_status = {
    'sirene_ativa': False,
    'mutado': False,
    'ultima_atualizacao': None
}

# ========== ROTAS PRINCIPAIS ==========
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/sos')
def sos():
    return render_template('sos.html')

# Compatibilidade: rota antiga (se existia) aponta para SOS
@app.route('/professor')
def professor():
    return render_template('sos.html')


@app.route('/central')
def central():
    expected = (os.environ.get('CENTRAL_PASSWORD') or '').strip()
    if expected and not session.get('central_auth'):
        return redirect(url_for('login_central'))
    return render_template('central.html')

@app.route('/painel_publico')
def painel_publico():
    return render_template('painel_publico.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/login_central', methods=['GET','POST'])
def login_central():
    # Se CENTRAL_PASSWORD estiver definido, exige senha; caso contrário, libera.
    if request.method == 'POST':
        senha = (request.form.get('senha') or request.form.get('password') or '').strip()
        expected = (os.environ.get('CENTRAL_PASSWORD') or '').strip()
        if expected and senha != expected:
            return render_template('login_central.html', erro='Senha incorreta.')
        session['central_auth'] = True
        return redirect(url_for('central'))
    return render_template('login_central.html', erro=None)

# ========== SISTEMA DE ÁUDIO ==========
@app.route('/play-alarm')
def play_alarm():
    try:
        return send_file('static/siren.wav.mp3')
    except FileNotFoundError:
        return "Arquivo de áudio não encontrado", 404

@app.route('/tocar_sirene')
def tocar_sirene():
    try:
        return send_file('static/siren.wav.mp3')
    except Exception as e:
        return f"Erro ao carregar sirene: {str(e)}", 500

# ========== APIs DO SISTEMA ==========

# ✅ ROTA CORRIGIDA: /api/alert com POST
@app.route('/api/alert', methods=['POST'])
def receber_alerta():
    try:
        data = request.get_json() or {}
        print("Dados recebidos:", data)  # Debug

        # Compatibilidade (projetos antigos): teacher/room continuam aceitos
        caller = (data.get('caller') or data.get('teacher') or '—')
        location = (data.get('location') or data.get('room') or 'Local não informado')
        occ_type = (data.get('type') or data.get('occ_type') or 'Ocorrência')
        description = (data.get('description') or 'Sem descrição')
        contact = (data.get('contact') or '')
        lat = data.get('lat')
        lng = data.get('lng')
        accuracy = data.get('accuracy')

        now = datetime.datetime.now(TZ)

        novo_alerta = {
            'id': len(alertas) + 1,
            'caller': caller,
            'location': location,
            'type': occ_type,
            'description': description,
            'contact': contact,
            'timestamp': now.strftime('%d/%m/%Y %H:%M:%S'),
            'resolved': False,
            'ts': now.strftime('%d/%m/%Y %H:%M:%S'),
            'lat': lat,
            'lng': lng,
            'accuracy': accuracy,
        }

        alertas.insert(0, novo_alerta)

        # Ativa sirene (na central/portaria)
        sistema_status['sirene_ativa'] = True

        return jsonify({'ok': True, 'alert': novo_alerta})
    except Exception as e:
        logging.exception("Erro ao receber alerta")
        return jsonify({'ok': False, 'error': str(e)}), 500

# ✅ ROTA CORRIGIDA: /api/status
@app.route('/api/status', methods=['GET'])
def status_sistema():
    try:
        alertas_ativos = [a for a in alertas if not a['resolved']]
        
        return jsonify({
            'ok': True,
            'siren': sistema_status['sirene_ativa'],
            'muted': sistema_status['mutado'],
            'alerts': alertas,
            'active_alerts': len(alertas_ativos),
            'last_update': sistema_status['ultima_atualizacao']
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# ✅ ROTA CORRIGIDA: /api/siren com POST
@app.route('/api/siren', methods=['POST'])
def controlar_sirene():
    try:
        data = request.get_json()
        action = data.get('action')
        
        if action == 'on':
            sistema_status['sirene_ativa'] = True
            sistema_status['mutado'] = False
        elif action == 'off':
            sistema_status['sirene_ativa'] = False
            sistema_status['mutado'] = False
        elif action == 'mute':
            sistema_status['mutado'] = True
            
        sistema_status['ultima_atualizacao'] = datetime.datetime.now(TZ).isoformat()
        
        return jsonify({'ok': True, 'siren': sistema_status['sirene_ativa'], 'muted': sistema_status['mutado']})
        
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# ✅ ROTA CORRIGIDA: /api/resolve com POST
@app.route('/api/resolve', methods=['POST'])
def resolver_alerta():
    try:
        for alerta in alertas:
            if not alerta['resolved']:
                alerta['resolved'] = True
                break
                
        alertas_ativos = [a for a in alertas if not a['resolved']]
        if not alertas_ativos:
            sistema_status['sirene_ativa'] = False
            
        sistema_status['ultima_atualizacao'] = datetime.datetime.now(TZ).isoformat()
        
        return jsonify({'ok': True})
        
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# ✅ ROTA CORRIGIDA: /api/clear com POST
@app.route('/api/clear', methods=['POST'])
def limpar_alertas():
    try:
        alertas.clear()
        sistema_status['sirene_ativa'] = False
        sistema_status['ultima_atualizacao'] = datetime.datetime.now(TZ).isoformat()
        
        return jsonify({'ok': True})
        
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# ✅ ROTA CORRIGIDA: /acionar_alerta com POST
@app.route('/acionar_alerta', methods=['POST'])
def acionar_alerta():
    try:
        now = datetime.datetime.now(TZ)
        novo_alerta = {
            'id': len(alertas) + 1,
            'teacher': 'Morador',
            'room': 'Local não informado',
            'description': 'Alerta de pânico acionado',
            'timestamp': now.strftime('%d/%m/%Y %H:%M:%S'),
            'resolved': False,
            'ts': now.strftime('%H:%M:%S')
        }
        
        alertas.append(novo_alerta)
        sistema_status['sirene_ativa'] = True
        sistema_status['ultima_atualizacao'] = datetime.datetime.now(TZ).isoformat()
        
        return jsonify({
            'success': True,
            'message': 'Alerta de pânico acionado! Sirene ativada.',
            'alerta': novo_alerta
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro: {str(e)}'
        }), 500

# Health check
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'})


@app.route('/report.pdf')
def report_pdf():
    """Gera um PDF simples com o histórico de alertas (compatível com o botão da Central)."""
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    now = datetime.datetime.now(TZ)
    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "CONDO-SAFE24 – Relatório de Alertas")
    y -= 18
    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"Gerado em: {now.strftime('%d/%m/%Y %H:%M:%S')}")
    y -= 25

    c.setFont("Helvetica-Bold", 11)
    c.drawString(40, y, "ID")
    c.drawString(70, y, "Data/Hora")
    c.drawString(170, y, "Tipo")
    c.drawString(300, y, "Local")
    c.drawString(510, y, "Status")
    y -= 12
    c.line(40, y, width - 40, y)
    y -= 14

    c.setFont("Helvetica", 9)
    for a in alertas[:120]:
        if y < 60:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 9)

        status = "Atendido" if a.get('resolved') else "Pendente"
        c.drawString(40, y, str(a.get('id', '')))
        c.drawString(70, y, (a.get('timestamp') or '')[:19])
        c.drawString(170, y, (a.get('type') or '')[:20])
        c.drawString(300, y, (a.get('location') or '')[:35])
        c.drawString(510, y, status)
        y -= 14

    c.save()
    buf.seek(0)
    return send_file(buf, mimetype='application/pdf', as_attachment=False, download_name='condo-safe24-relatorio.pdf')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)  # Debug=True para ver erros
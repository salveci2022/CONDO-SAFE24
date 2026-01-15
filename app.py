from flask import Flask, render_template, send_file, jsonify, request, redirect, url_for, session
import os
import datetime
import logging

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'condo-safe24-secret')  # necessário para login da central

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
        return send_file('static/siren.wav')
    except FileNotFoundError:
        return "Arquivo de áudio não encontrado", 404

@app.route('/tocar_sirene')
def tocar_sirene():
    try:
        return send_file('static/siren.wav')
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

        novo_alerta = {
            'id': len(alertas) + 1,
            'caller': caller,
            'location': location,
            'type': occ_type,
            'description': description,
            'contact': contact,
            'timestamp': datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            'resolved': False,
            'ts': datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
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
            
        sistema_status['ultima_atualizacao'] = datetime.datetime.now().isoformat()
        
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
            
        sistema_status['ultima_atualizacao'] = datetime.datetime.now().isoformat()
        
        return jsonify({'ok': True})
        
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# ✅ ROTA CORRIGIDA: /api/clear com POST
@app.route('/api/clear', methods=['POST'])
def limpar_alertas():
    try:
        alertas.clear()
        sistema_status['sirene_ativa'] = False
        sistema_status['ultima_atualizacao'] = datetime.datetime.now().isoformat()
        
        return jsonify({'ok': True})
        
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# ✅ ROTA CORRIGIDA: /acionar_alerta com POST
@app.route('/acionar_alerta', methods=['POST'])
def acionar_alerta():
    try:
        novo_alerta = {
            'id': len(alertas) + 1,
            'teacher': 'Morador',
            'room': 'Local não informado',
            'description': 'Alerta de pânico acionado',
            'timestamp': datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            'resolved': False,
            'ts': datetime.datetime.now().strftime('%H:%M:%S')
        }
        
        alertas.append(novo_alerta)
        sistema_status['sirene_ativa'] = True
        sistema_status['ultima_atualizacao'] = datetime.datetime.now().isoformat()
        
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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)  # Debug=True para ver erros
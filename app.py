from flask import Flask, render_template, send_file, jsonify, request, redirect, url_for, session
import os
from pathlib import Path
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


# =================== SEGURANÇA (NÍVEL ALTO – CHAVE POR CLIENTE) ===================
# Como funciona:
# - Cada condomínio recebe uma CHAVE (ex.: ?key=COND-ABCD1234)
# - O painel /sos só funciona com chave válida
# - As APIs críticas exigem autenticação (Central/Admin)

KEYS_FILE = Path(os.environ.get('CONDO_KEYS_FILE', 'data/keys.json'))

def _ensure_data_dir():
    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)

def _load_keys():
    # Retorna dict: {key: {name: str, active: bool}}
    env_json = (os.environ.get('CONDO_KEYS_JSON') or '').strip()
    if env_json:
        try:
            data = __import__('json').loads(env_json)
            out = {}
            for k, v in (data or {}).items():
                if isinstance(v, dict):
                    out[str(k)] = {
                        'name': str(v.get('name', 'Condomínio')).strip() or 'Condomínio',
                        'active': bool(v.get('active', True)),
                    }
                else:
                    out[str(k)] = {'name': str(v).strip() or 'Condomínio', 'active': True}
            return out
        except Exception:
            return {}

    try:
        if KEYS_FILE.exists():
            data = __import__('json').loads(KEYS_FILE.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                out = {}
                for k, v in data.items():
                    if isinstance(v, dict):
                        out[str(k)] = {
                            'name': str(v.get('name', 'Condomínio')).strip() or 'Condomínio',
                            'active': bool(v.get('active', True)),
                        }
                    else:
                        out[str(k)] = {'name': str(v).strip() or 'Condomínio', 'active': True}
                return out
    except Exception:
        pass

    # Fallback seguro (evita SOS aberto): cria uma chave demo
    _ensure_data_dir()
    demo = {'DEMO-1234': {'name': 'DEMO', 'active': True}}
    try:
        KEYS_FILE.write_text(__import__('json').dumps(demo, ensure_ascii=False, indent=2), encoding='utf-8')
    except Exception:
        pass
    return demo

def _is_valid_client_key(key: str):
    if not key:
        return False
    info = (_load_keys() or {}).get(key)
    return bool(info and info.get('active', True))

def _client_info(key: str):
    return (_load_keys() or {}).get(key)

def _require_client_key():
    # Valida chave vinda por query (?key=), header (X-CLIENT-KEY), JSON (key) ou sessão
    key = (request.args.get('key') or '').strip()
    if not key:
        key = (request.headers.get('X-CLIENT-KEY') or '').strip()
    if not key:
        data = request.get_json(silent=True) or {}
        key = (data.get('key') or '').strip()
    if not key:
        key = (session.get('client_key') or '').strip()

    if not _is_valid_client_key(key):
        return None
    return key

def _require_central_or_admin():
    expected_central = (os.environ.get('CENTRAL_PASSWORD') or '').strip()
    expected_admin = (os.environ.get('ADMIN_PASSWORD') or '').strip()

    central_ok = (not expected_central) or bool(session.get('central_auth'))
    admin_ok = (not expected_admin) or bool(session.get('admin_auth'))
    return central_ok or admin_ok

# ========== ROTAS PRINCIPAIS ==========
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/sos')
def sos():
    # Se vier ?key=..., valida e guarda na sessão (remove da URL depois)
    key_q = (request.args.get('key') or '').strip()
    if key_q:
        if not _is_valid_client_key(key_q):
            return render_template('forbidden.html', msg='Chave inválida ou desativada.'), 403
        session['client_key'] = key_q
        info = _client_info(key_q) or {}
        session['client_name'] = info.get('name', 'Condomínio')
        return redirect(url_for('sos'))

    # Exige chave válida na sessão
    key = (session.get('client_key') or '').strip()
    if not _is_valid_client_key(key):
        return render_template('forbidden.html', msg='Acesso restrito. Use o link oficial com chave do seu condomínio.'), 403

    return render_template('sos.html', client_name=session.get('client_name', 'Condomínio'))

# Compatibilidade: rota antiga (se existia) aponta para SOS
@app.route('/professor')
def professor():
    return redirect(url_for('sos'))


@app.route('/central')
def central():
    expected = (os.environ.get('CENTRAL_PASSWORD') or '').strip()
    if expected and not session.get('central_auth'):
        return redirect(url_for('login_central'))
    return render_template('central.html')

@app.route('/painel_publico')
def painel_publico():
    # Histórico deve ser protegido (somente Central/Admin)
    expected_c = (os.environ.get('CENTRAL_PASSWORD') or '').strip()
    expected_a = (os.environ.get('ADMIN_PASSWORD') or '').strip()
    if (expected_c or expected_a) and not _require_central_or_admin():
        return redirect(url_for('login_central'))
    return render_template('painel_publico.html')

@app.route('/admin')
def admin():
    expected = (os.environ.get('ADMIN_PASSWORD') or '').strip()
    if expected and not session.get('admin_auth'):
        return redirect(url_for('login_admin'))
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


@app.route('/login_admin', methods=['GET','POST'])
def login_admin():
    if request.method == 'POST':
        senha = (request.form.get('senha') or request.form.get('password') or '').strip()
        expected = (os.environ.get('ADMIN_PASSWORD') or '').strip()
        if expected and senha != expected:
            return render_template('login_admin.html', erro='Senha incorreta.')
        session['admin_auth'] = True
        return redirect(url_for('admin'))
    return render_template('login_admin.html', erro=None)

@app.route('/logout_admin')
def logout_admin():
    session.pop('admin_auth', None)
    return redirect(url_for('login_admin'))


@app.route('/logout_central')
def logout_central():
    """Encerra a sessão da Central e volta para a tela de login."""
    session.pop('central_auth', None)
    return redirect(url_for('login_central'))

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
    client_key = _require_client_key()
    if not client_key:
        return jsonify({'ok': False, 'error': 'Acesso negado (chave inválida).'}), 403
    try:
        data = request.get_json() or {}
        print("Dados recebidos:", data)  # Debug

        # Compatibilidade (projetos antigos): teacher/room continuam aceitos
        caller = (data.get('caller') or data.get('teacher') or '—')
        # No CONDO-SAFE24 a localização principal é o MAPA (GPS). Mantemos este campo apenas por compatibilidade.
        location = (data.get('location') or data.get('room') or '')
        occ_type = (data.get('type') or data.get('occ_type') or 'Ocorrência')
        description = (data.get('description') or 'Sem descrição')
        contact = (data.get('contact') or '')
        lat = data.get('lat')
        lng = data.get('lng')
        accuracy = data.get('accuracy')

        maps_url = None
        if lat is not None and lng is not None and str(lat) != '' and str(lng) != '':
            maps_url = f"https://www.google.com/maps?q={lat},{lng}"

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
            'maps_url': maps_url,
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
    if not _require_central_or_admin():
        return jsonify({'ok': False, 'error': 'Acesso negado.'}), 401
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
    if not _require_central_or_admin():
        return jsonify({'ok': False, 'error': 'Acesso negado.'}), 401
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
    if not _require_central_or_admin():
        return jsonify({'ok': False, 'error': 'Acesso negado.'}), 401
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
    if not _require_central_or_admin():
        return jsonify({'ok': False, 'error': 'Acesso negado.'}), 401
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


# ========== ADMIN: CHAVES POR CLIENTE ==========
@app.route('/api/keys', methods=['GET'])
def list_keys():
    if not session.get('admin_auth'):
        return jsonify({'ok': False, 'error': 'Não autorizado'}), 401
    return jsonify({'ok': True, 'keys': _load_keys()})

@app.route('/api/keys', methods=['POST'])
def create_key():
    if not session.get('admin_auth'):
        return jsonify({'ok': False, 'error': 'Não autorizado'}), 401
    data = request.get_json() or {}
    name = (data.get('name') or 'Condomínio').strip()
    # gera uma chave simples, forte o bastante para uso comercial
    import secrets
    new_key = 'COND-' + secrets.token_urlsafe(10).replace('-', '').replace('_', '')[:12].upper()
    keys = _load_keys()
    keys[new_key] = {'name': name, 'active': True}
    try:
        _ensure_data_dir()
        KEYS_FILE.write_text(__import__('json').dumps(keys, ensure_ascii=False, indent=2), encoding='utf-8')
    except Exception:
        pass
    return jsonify({'ok': True, 'key': new_key, 'name': name})

@app.route('/api/keys/toggle', methods=['POST'])
def toggle_key():
    if not session.get('admin_auth'):
        return jsonify({'ok': False, 'error': 'Não autorizado'}), 401
    data = request.get_json() or {}
    key = (data.get('key') or '').strip()
    active = bool(data.get('active', True))
    keys = _load_keys()
    if key not in keys:
        return jsonify({'ok': False, 'error': 'Chave não encontrada'}), 404
    info = keys.get(key) or {}
    if isinstance(info, dict):
        info['active'] = active
        keys[key] = info
    else:
        keys[key] = {'name': str(info), 'active': active}
    try:
        _ensure_data_dir()
        KEYS_FILE.write_text(__import__('json').dumps(keys, ensure_ascii=False, indent=2), encoding='utf-8')
    except Exception:
        pass
    return jsonify({'ok': True})

# Health check
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'})


@app.route('/report.pdf')
def report_pdf():
    if not _require_central_or_admin():
        return redirect(url_for('login_central'))

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
    c.drawString(300, y, "GPS")
    c.drawString(420, y, "Mapa")
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

        lat = a.get('lat')
        lng = a.get('lng')
        acc = a.get('accuracy')
        gps_txt = '—'
        if lat is not None and lng is not None and str(lat) != '' and str(lng) != '':
            try:
                gps_txt = f"{float(lat):.6f}, {float(lng):.6f}"
            except Exception:
                gps_txt = f"{lat}, {lng}"
            if acc not in (None, '', 0, '0'):
                try:
                    gps_txt += f" (±{int(float(acc))}m)"
                except Exception:
                    pass
        c.drawString(300, y, gps_txt[:22])

        maps_url = a.get('maps_url')
        if maps_url:
            c.setFillColorRGB(0, 0.6, 0.8)
            c.drawString(420, y, "Abrir")
            c.linkURL(maps_url, (420, y-2, 455, y+10), relative=0)
            c.setFillColorRGB(0, 0, 0)
        else:
            c.drawString(420, y, "—")

        c.drawString(510, y, status)
        y -= 14

    c.save()
    buf.seek(0)
    return send_file(buf, mimetype='application/pdf', as_attachment=False, download_name='condo-safe24-relatorio.pdf')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)  # Debug=True para ver erros
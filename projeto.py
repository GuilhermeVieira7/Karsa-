# verificador_sites.py criado por Guilherme Vieira :D

import requests
import whois
import socket
import ssl
import datetime
from urllib.parse import urlparse
from flask import Flask, render_template, request

app = Flask(__name__)

SAFE_DOMAINS = ['correios.com.br', 'www.correios.com.br']
GOOGLE_API_KEY = 'SUA_CHAVE_AQUI'  # Aqui você coloca a sua chave do Google Safe Browsing API
PHISHTANK_API_KEY = 'SUA_CHAVE_AQUI'  # (Isso é opcional, vai depender muito da API que vocẽ está utilizando)


def verificar_https(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                dias_restantes = (exp_date - datetime.datetime.utcnow()).days
                return True, dias_restantes
    except Exception as e:
        return False, str(e)


def verificar_dominio_whois(dominio):
    try:
        info = whois.whois(dominio)
        return info.creation_date
    except Exception as e:
        return f"Erro no WHOIS: {e}"


def verificar_google_safe_browsing(url):
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {
                "clientId": "verificador-sites",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(endpoint, json=payload)
        data = response.json()
        return bool(data.get("matches"))
    except Exception as e:
        return False


def verificar_similaridade(dominio):
    for legit in SAFE_DOMAINS:
        if legit in dominio or dominio.endswith(legit):
            return True
    return False


def calcular_score(https_ok, dominio_novo, blacklistado, similar):
    score = 100
    if not https_ok:
        score -= 30
    if dominio_novo:
        score -= 25
    if blacklistado:
        score -= 30
    if not similar:
        score -= 15
    return max(score, 0)


def analisar_site(url):
    parsed = urlparse(url)
    dominio = parsed.hostname

    https_ok, https_info = verificar_https(url)
    criacao = verificar_dominio_whois(dominio)
    blacklistado = verificar_google_safe_browsing(url)
    similar = verificar_similaridade(dominio)

    dominio_novo = False
    if isinstance(criacao, datetime.datetime):
        dias = (datetime.datetime.utcnow() - criacao).days
        dominio_novo = dias < 180
    else:
        dominio_novo = True

    score = calcular_score(https_ok, dominio_novo, blacklistado, similar)

    return {
        "url": url,
        "https_ok": https_ok,
        "https_info": https_info,
        "criacao": criacao,
        "blacklistado": blacklistado,
        "similar": similar,
        "dominio_novo": dominio_novo,
        "score": score
    }


@app.route("/", methods=["GET", "POST"])
def index():
    resultado = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            if not url.startswith("http"):
                url = "http://" + url
            resultado = analisar_site(url)
    return render_template("index.html", resultado=resultado)


if __name__ == "__main__":
    app.run(debug=True)

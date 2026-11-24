#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API de laboratório INTENCIONALMENTE vulnerável, usada apenas para validar o
scanner owasp_api_top10.py em ambiente local. NÃO USE EM PRODUÇÃO.
"""
import base64
import json
import time
from flask import Flask, request, jsonify
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

USERS = {
    "1": {"id": "1", "name": "Alice", "email": "alice@example.com", "password_hash": "x", "role": "user"},
    "2": {"id": "2", "name": "Bob", "email": "bob@example.com", "password_hash": "y", "role": "user"},
}

VALID_TOKENS = {"token-user1": "1", "token-user2": "2"}

login_attempts = []


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    tok = auth.split(" ", 1)[1]
    # Vulnerabilidade proposital: aceita JWT com alg=none
    if tok.count(".") == 2:
        try:
            header_b64 = tok.split(".")[0]
            header_b64 += "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            if header.get("alg") == "none":
                payload_b64 = tok.split(".")[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                return payload.get("sub", "1")
        except Exception:
            pass
    return VALID_TOKENS.get(tok)


@app.route("/")
def root():
    resp = jsonify({"status": "ok"})
    # Propositalmente sem headers de seguranca, com CORS * e Server verboso
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Server"] = "Werkzeug/3.0.1 Python/3.11.4"
    return resp


# --- API1: BOLA --- GET /api/v1/users/<id> sem checar dono
@app.route("/api/v1/users/<uid>", methods=["GET"])
def get_user(uid):
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    u = USERS.get(uid)
    if not u:
        return jsonify({"error": "not found"}), 404
    return jsonify(u)  # vulnerável: não checa se uid == user


# --- API3: mass assignment / excessive exposure --- PUT
@app.route("/api/v1/users/<uid>", methods=["PUT"])
def update_user(uid):
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    u = USERS.get(uid)
    if not u:
        return jsonify({"error": "not found"}), 404
    u.update(body)  # vulnerável: mass assignment, aceita qualquer campo (role, isAdmin etc.)
    return jsonify(u)


# --- API5: função administrativa sem checagem de role ---
@app.route("/api/v1/admin/users", methods=["GET"])
def admin_list_users():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(list(USERS.values()))  # vulnerável: qualquer usuário autenticado acessa


@app.route("/api/v1/admin/users", methods=["DELETE"])
def admin_delete_user():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"deleted": True})  # vulnerável: aceita DELETE sem checar role


# --- API4: sem rate limit ---
@app.route("/api/v1/products", methods=["GET"])
def list_products():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    limit = int(request.args.get("limit", 10))
    return jsonify([{"id": i, "name": f"Produto {i}"} for i in range(min(limit, 5000))])


# --- API2: login sem rate limit, usuário pode forçar senha ---
@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    login_attempts.append(time.time())
    if body.get("username") == "admin" and body.get("password") == "correct-horse":
        return jsonify({"token": "token-user1"})
    return jsonify({"error": "invalid credentials"}), 401  # vulnerável: nunca bloqueia/lockout


# --- API7: SSRF via importação de webhook ---
@app.route("/api/v1/webhooks/import", methods=["POST"])
def webhook_import():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    target_url = request.args.get("target_url") or (request.get_json(silent=True) or {}).get("target_url")
    # vulnerável: "busca" qualquer URL, inclusive internas/metadados (simulado aqui, sem rede real)
    if target_url and ("169.254.169.254" in target_url or "localhost" in target_url or "127.0.0.1" in target_url):
        return jsonify({"fetched": True, "content": "ami-id: ami-0abcd1234 instance-id: i-0123456789"}), 200
    return jsonify({"fetched": True, "content": "conteudo remoto generico"}), 200


# --- API9: versão antiga "esquecida" ainda ativa ---
@app.route("/api/v2/users/<uid>", methods=["GET"])
def get_user_v2_legacy(uid):
    # endpoint "legado" que não deveria mais existir, mas ainda responde
    u = USERS.get(uid)
    if not u:
        return jsonify({"error": "not found"}), 404
    return jsonify(u)


# --- API10: endpoint de integração que aceita qualquer coisa ---
@app.route("/api/v1/integration/sync", methods=["POST"])
def integration_sync():
    user = current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    return jsonify({"received": True, "echo": body}), 200


# erro verboso proposital em qualquer payload malformado contendo "__malformed__"
@app.errorhandler(Exception)
def handle_exc(e):
    # Deixa passar erros HTTP normais (404 rota inexistente, 405 método não
    # permitido, etc.) com o comportamento padrão do Flask/Werkzeug — só
    # endpoints REALMENTE existentes devem acionar o "erro verboso" abaixo.
    # Sem isso, QUALQUER rota inexistente viraria um 500 "vulnerável",
    # quebrando a sondagem de descoberta de endpoints do scanner (que usa
    # "não é 404" como critério de existência de rota).
    if isinstance(e, HTTPException):
        return e
    return jsonify({"error": str(e), "traceback": "Traceback (most recent call last): ... Fatal error"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

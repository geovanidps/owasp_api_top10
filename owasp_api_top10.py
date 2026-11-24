#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OWASP API Security Top 10 (2023) - Scanner Automatizado
=========================================================

Ferramenta educacional de pentest para avaliar APIs REST contra as 10
categorias do OWASP API Security Top 10 (2023), com tentativas reais de
bypass/exploração para confirmar (e não apenas sugerir) cada vulnerabilidade.

!!! AVISO LEGAL / USO AUTORIZADO !!!
Esta ferramenta executa testes ATIVOS (tentativas de bypass de autenticação,
autorização, rate limiting, etc.) contra a API alvo. Use SOMENTE em sistemas
que você possui ou para os quais tenha autorização EXPLÍCITA e por escrito
para realizar testes de segurança (ex.: ambiente de laboratório, CTF, ou
contrato de pentest assinado). Testar sistemas de terceiros sem autorização
é crime na maioria das jurisdições (no Brasil, pode se enquadrar na Lei
12.737/2012 - Lei Carolina Dieckmann, além de outros dispositivos do Código
Penal). O autor/professor e o uso em sala de aula devem sempre reforçar essa
regra aos alunos.

Autor: gerado para fins didáticos (disciplina de Cibersegurança)
Compatibilidade: Python 3.8+
Dependências: requests (obrigatória), colorama (opcional, para cores)
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[ERRO] A biblioteca 'requests' é obrigatória. Instale com: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_OK = True
except ImportError:
    COLOR_OK = False

    class _Dummy:
        def __getattr__(self, item):
            return ""

    Fore = _Dummy()
    Style = _Dummy()

# Silencia avisos de SSL quando o usuário optar por verify=False em labs
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# ---------------------------------------------------------------------------
# Modelos de dados
# ---------------------------------------------------------------------------

class Status(str, Enum):
    VULNERABLE = "VULNERÁVEL"
    SAFE = "PROTEGIDO"
    INCONCLUSIVE = "INCONCLUSIVO"
    SKIPPED = "IGNORADO"
    ERROR = "ERRO"


@dataclass
class Finding:
    api_id: str           # ex: "API1:2023"
    title: str            # ex: "Broken Object Level Authorization"
    endpoint: str
    status: Status
    detail: str
    evidence: str = ""
    recommendation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Endpoint:
    path: str                       # ex: "/api/users/{id}"
    method: str = "GET"
    id_param: Optional[str] = None  # nome do parâmetro de objeto, ex: "id"
    sample_id: Optional[str] = None
    alt_id: Optional[str] = None    # id de outro objeto/usuário para IDOR cruzado
    auth_required: bool = True
    body: Optional[dict] = None
    description: str = ""
    sensitive_fields: List[str] = field(default_factory=list)  # campos que não deveriam vazar
    privileged: bool = False        # endpoint administrativo (para API5)
    url_param_for_ssrf: Optional[str] = None  # nome do parâmetro que aceita URL (para API7)


@dataclass
class ScanConfig:
    base_url: str
    primary_token: str = ""
    secondary_token: str = ""       # token de um segundo usuário, para testes cruzados de IDOR
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    extra_headers: Dict[str, str] = field(default_factory=dict)
    endpoints: List[Endpoint] = field(default_factory=list)
    login_endpoint: Optional[str] = None
    login_body_template: Optional[dict] = None     # ex: {"username": "admin", "password": "{password}"}
    rate_limit_requests: int = 40
    rate_limit_window_seconds: float = 5.0
    timeout: float = 8.0
    verify_ssl: bool = True
    proxy: Optional[str] = None
    documented_version: Optional[str] = None       # ex: "v2" (para teste de inventário)

    def auth_headers(self, token: Optional[str] = None) -> Dict[str, str]:
        headers = dict(self.extra_headers)
        tok = token if token is not None else self.primary_token
        if tok:
            headers[self.auth_header] = f"{self.auth_scheme} {tok}".strip()
        return headers


# ---------------------------------------------------------------------------
# Cliente HTTP fino (centraliza timeout, proxy, verify, tratamento de erro)
# ---------------------------------------------------------------------------

class HttpClient:
    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.proxy:
            self.session.proxies.update({"http": cfg.proxy, "https": cfg.proxy})

    def request(self, method: str, path: str, headers: Optional[dict] = None,
                json_body: Optional[dict] = None, params: Optional[dict] = None,
                allow_redirects: bool = True) -> Optional[requests.Response]:
        url = path if path.startswith("http") else urljoin(self.cfg.base_url, path.lstrip("/"))
        try:
            return self.session.request(
                method=method.upper(),
                url=url,
                headers=headers or {},
                json=json_body,
                params=params,
                timeout=self.cfg.timeout,
                verify=self.cfg.verify_ssl,
                allow_redirects=allow_redirects,
            )
        except RequestException as exc:
            return None  # tratado pelo chamador como falha de rede/inconclusivo

    def resolve_path(self, ep: Endpoint, obj_id: Optional[str] = None) -> str:
        p = ep.path
        if ep.id_param and "{" + ep.id_param + "}" in p:
            p = p.replace("{" + ep.id_param + "}", str(obj_id if obj_id is not None else ep.sample_id))
        return p


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|passwd|senha|secret|token|api[_-]?key|ssn|cpf|credit[_-]?card|"
    r"cartao|salary|salario|hash|private[_-]?key|access[_-]?token|refresh[_-]?token)",
    re.IGNORECASE,
)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
]

INTERNAL_PROBE_URLS = [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata (AWS/Azure/GCP)
    "http://127.0.0.1:80/",
    "http://localhost/",
    "file:///etc/passwd",
]


def find_sensitive_keys(obj: Any, path: str = "") -> List[str]:
    """Varre recursivamente um JSON procurando chaves que soem sensíveis."""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{path}.{k}" if path else k
            if SENSITIVE_KEY_PATTERNS.search(str(k)):
                hits.append(full)
            hits.extend(find_sensitive_keys(v, full))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:5]):  # limita para não explodir em listas grandes
            hits.extend(find_sensitive_keys(item, f"{path}[{i}]"))
    return hits


def safe_json(resp: Optional[requests.Response]) -> Any:
    if resp is None:
        return None
    try:
        return resp.json()
    except Exception:
        return None


def forge_jwt_alg_none(token: str) -> Optional[str]:
    """Reconstrói um JWT trocando o alg para 'none' e removendo a assinatura.
    Técnica clássica de bypass de autenticação (CVE-class: JWT alg=none)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    def b64url_decode(s: str) -> bytes:
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s.encode())

    def b64url_encode(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception:
        return None
    header["alg"] = "none"
    new_header = b64url_encode(json.dumps(header).encode())
    # payload é mantido como está (poderia também ser adulterado, ex: role=admin)
    return f"{new_header}.{parts[1]}."


def forge_jwt_privilege_escalation(token: str, claim: str = "role", value: Any = "admin") -> Optional[str]:
    """Tenta adulterar um claim do payload (sem assinar) - só funciona se o
    servidor não validar a assinatura corretamente."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    def b64url_decode(s: str) -> bytes:
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s.encode())

    def b64url_encode(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None
    header["alg"] = "none"
    payload[claim] = value
    new_header = b64url_encode(json.dumps(header).encode())
    new_payload = b64url_encode(json.dumps(payload).encode())
    return f"{new_header}.{new_payload}."


def looks_like_jwt(token: str) -> bool:
    return bool(token) and token.count(".") == 2


# ---------------------------------------------------------------------------
# API1:2023 - Broken Object Level Authorization (BOLA)
# ---------------------------------------------------------------------------

def test_api1_bola(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings = []
    candidates = [e for e in cfg.endpoints if e.id_param]
    if not candidates:
        findings.append(Finding("API1:2023", "Broken Object Level Authorization", "-",
                                 Status.SKIPPED, "Nenhum endpoint com id_param configurado."))
        return findings

    for ep in candidates:
        base_path = client.resolve_path(ep)
        headers = cfg.auth_headers()

        # 1) Tenta IDs adjacentes (enumeração sequencial)
        tried_ids = []
        if ep.sample_id and str(ep.sample_id).isdigit():
            base_num = int(ep.sample_id)
            tried_ids = [str(base_num - 1), str(base_num + 1)]
        elif ep.alt_id:
            tried_ids = [ep.alt_id]

        vulnerable_hits = []
        for tid in tried_ids:
            path = client.resolve_path(ep, tid)
            resp = client.request(ep.method, path, headers=headers, json_body=ep.body)
            if resp is None:
                continue
            if resp.status_code == 200 and resp.content:
                vulnerable_hits.append((tid, resp.status_code))

        # 2) Cross-user: token do usuário 2 acessando objeto do usuário 1
        cross_user_hit = None
        if cfg.secondary_token and ep.sample_id:
            headers2 = cfg.auth_headers(cfg.secondary_token)
            resp2 = client.request(ep.method, base_path, headers=headers2, json_body=ep.body)
            if resp2 is not None and resp2.status_code == 200 and resp2.content:
                cross_user_hit = resp2.status_code

        if vulnerable_hits or cross_user_hit:
            ev = []
            if vulnerable_hits:
                ev.append(f"IDs adjacentes acessíveis sem dono: {vulnerable_hits}")
            if cross_user_hit:
                ev.append(f"Token de usuário secundário acessou objeto do usuário primário "
                          f"em '{base_path}' (HTTP {cross_user_hit}).")
            findings.append(Finding(
                "API1:2023", "Broken Object Level Authorization", base_path,
                Status.VULNERABLE,
                "Bypass de BOLA bem-sucedido: foi possível acessar objetos de outro "
                "usuário/ID sem checagem de propriedade.",
                evidence=" | ".join(ev),
                recommendation="Implemente verificação de propriedade do objeto (ownership check) "
                               "no backend para cada operação, usando o ID do usuário autenticado, "
                               "nunca confiando apenas no ID vindo da URL/payload.",
            ))
        else:
            findings.append(Finding(
                "API1:2023", "Broken Object Level Authorization", base_path,
                Status.SAFE if tried_ids or cross_user_hit is not None else Status.INCONCLUSIVE,
                "Não foi possível acessar objetos de outros usuários/IDs com os dados de teste fornecidos."
                if tried_ids else "Configure 'alt_id' ou 'secondary_token' para um teste mais conclusivo.",
            ))
    return findings


# ---------------------------------------------------------------------------
# API2:2023 - Broken Authentication
# ---------------------------------------------------------------------------

def test_api2_broken_auth(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings = []
    protected = [e for e in cfg.endpoints if e.auth_required]
    if not protected:
        findings.append(Finding("API2:2023", "Broken Authentication", "-",
                                 Status.SKIPPED, "Nenhum endpoint marcado como auth_required."))
        return findings

    # 1) Acesso sem nenhum token
    for ep in protected:
        path = client.resolve_path(ep)
        resp = client.request(ep.method, path, headers=cfg.extra_headers, json_body=ep.body)
        if resp is None:
            findings.append(Finding("API2:2023", "Broken Authentication", path, Status.ERROR,
                                     "Falha de rede ao testar acesso sem autenticação."))
            continue
        if resp.status_code < 400:
            findings.append(Finding(
                "API2:2023", "Broken Authentication", path, Status.VULNERABLE,
                "Bypass de autenticação: endpoint protegido respondeu sem exigir token.",
                evidence=f"HTTP {resp.status_code} sem header de autenticação.",
                recommendation="Garanta que todo endpoint sensível exija e valide um token "
                               "válido antes de processar a requisição (middleware de autenticação).",
            ))
        else:
            findings.append(Finding("API2:2023", "Broken Authentication", path, Status.SAFE,
                                     f"Requisição sem token corretamente rejeitada (HTTP {resp.status_code})."))

    # 2) Bypass via JWT alg=none, se o token parecer um JWT
    if cfg.primary_token and looks_like_jwt(cfg.primary_token):
        forged = forge_jwt_alg_none(cfg.primary_token)
        if forged:
            target = protected[0]
            path = client.resolve_path(target)
            headers = dict(cfg.extra_headers)
            headers[cfg.auth_header] = f"{cfg.auth_scheme} {forged}".strip()
            resp = client.request(target.method, path, headers=headers, json_body=target.body)
            if resp is not None and resp.status_code < 400:
                findings.append(Finding(
                    "API2:2023", "Broken Authentication", path, Status.VULNERABLE,
                    "Bypass de autenticação via JWT 'alg=none': o servidor aceitou um token "
                    "sem assinatura.",
                    evidence=f"HTTP {resp.status_code} com token forjado {forged[:40]}...",
                    recommendation="Nunca aceite 'none' como algoritmo de assinatura. Valide "
                                   "explicitamente o algoritmo esperado (whitelist) na biblioteca JWT.",
                ))
            else:
                code = resp.status_code if resp is not None else "sem resposta"
                findings.append(Finding("API2:2023", "Broken Authentication", path, Status.SAFE,
                                         f"Token JWT com alg=none corretamente rejeitado (HTTP {code})."))
        else:
            findings.append(Finding("API2:2023", "Broken Authentication", "-", Status.INCONCLUSIVE,
                                     "Token configurado não pôde ser decodificado como JWT."))
    else:
        findings.append(Finding("API2:2023", "Broken Authentication", "-", Status.SKIPPED,
                                 "primary_token não parece um JWT (header.payload.signature); "
                                 "teste de alg=none ignorado."))

    # 3) Ausência de rate limit no login (força bruta)
    if cfg.login_endpoint and cfg.login_body_template:
        attempts = 8
        codes = []
        start = time.time()
        for i in range(attempts):
            body = json.loads(json.dumps(cfg.login_body_template).replace(
                "{password}", f"wrong_pw_{i}_{uuid.uuid4().hex[:6]}"))
            resp = client.request("POST", cfg.login_endpoint, headers=cfg.extra_headers, json_body=body)
            codes.append(resp.status_code if resp is not None else -1)
        elapsed = time.time() - start
        throttled = any(c == 429 for c in codes) or codes.count(-1) > attempts // 2
        if not throttled:
            findings.append(Finding(
                "API2:2023", "Broken Authentication", cfg.login_endpoint, Status.VULNERABLE,
                f"Nenhum rate limiting/lockout detectado após {attempts} tentativas de login "
                f"inválidas em {elapsed:.1f}s — superfície para força bruta de credenciais.",
                evidence=f"Códigos HTTP retornados: {codes}",
                recommendation="Implemente rate limiting por IP/usuário, CAPTCHA progressivo e "
                               "bloqueio temporário de conta após N tentativas falhas.",
            ))
        else:
            findings.append(Finding("API2:2023", "Broken Authentication", cfg.login_endpoint, Status.SAFE,
                                     f"Rate limiting/bloqueio detectado durante tentativas de força bruta "
                                     f"(códigos: {codes})."))
    else:
        findings.append(Finding("API2:2023", "Broken Authentication", "-", Status.SKIPPED,
                                 "login_endpoint / login_body_template não configurados; "
                                 "teste de força bruta ignorado."))
    return findings


# ---------------------------------------------------------------------------
# API3:2023 - Broken Object Property Level Authorization
# (excessive data exposure + mass assignment)
# ---------------------------------------------------------------------------

def test_api3_property_auth(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings = []
    get_eps = [e for e in cfg.endpoints if e.method.upper() == "GET"]
    for ep in get_eps:
        path = client.resolve_path(ep)
        resp = client.request("GET", path, headers=cfg.auth_headers(), json_body=None)
        data = safe_json(resp)
        if data is None:
            continue
        hits = find_sensitive_keys(data)
        declared = set(ep.sensitive_fields or [])
        unexpected = [h for h in hits if h.split(".")[-1].split("[")[0] not in declared]
        if unexpected:
            findings.append(Finding(
                "API3:2023", "Broken Object Property Level Authorization", path, Status.VULNERABLE,
                "Exposição excessiva de dados: a resposta contém campos sensíveis que não "
                "deveriam ser retornados por padrão.",
                evidence=f"Campos suspeitos: {unexpected}",
                recommendation="Use DTOs/serializers explícitos por endpoint (allow-list de campos), "
                               "nunca serialize o objeto de domínio inteiro diretamente.",
            ))
        else:
            findings.append(Finding("API3:2023", "Broken Object Property Level Authorization", path,
                                     Status.SAFE, "Nenhum campo sensível não declarado encontrado na resposta."))

    # Mass assignment: tenta injetar campos privilegiados em requisições de escrita
    write_eps = [e for e in cfg.endpoints if e.method.upper() in ("POST", "PUT", "PATCH")]
    injected_fields = {"isAdmin": True, "is_admin": True, "role": "admin", "admin": True}
    for ep in write_eps:
        path = client.resolve_path(ep)
        body = dict(ep.body or {})
        body.update(injected_fields)
        resp = client.request(ep.method, path, headers=cfg.auth_headers(), json_body=body)
        if resp is None:
            continue
        resp_json = safe_json(resp)
        reflected = False
        if isinstance(resp_json, dict):
            for k in injected_fields:
                if resp_json.get(k) in (True, "admin"):
                    reflected = True
                    break
        if resp.status_code < 300 and reflected:
            findings.append(Finding(
                "API3:2023", "Broken Object Property Level Authorization", path, Status.VULNERABLE,
                "Mass assignment: foi possível definir campos privilegiados (ex.: isAdmin/role) "
                "enviando-os no corpo da requisição.",
                evidence=f"Resposta refletiu: { {k: v for k, v in (resp_json or {}).items() if k in injected_fields} }",
                recommendation="Nunca faça bind automático do payload inteiro para o modelo. "
                               "Use allow-list de campos editáveis por papel/endpoint.",
            ))
        elif resp.status_code < 300:
            findings.append(Finding("API3:2023", "Broken Object Property Level Authorization", path,
                                     Status.SAFE, "Campos privilegiados enviados não foram refletidos/aceitos."))
        else:
            findings.append(Finding("API3:2023", "Broken Object Property Level Authorization", path,
                                     Status.SAFE, f"Requisição de mass assignment rejeitada (HTTP {resp.status_code})."))
    if not get_eps and not write_eps:
        findings.append(Finding("API3:2023", "Broken Object Property Level Authorization", "-",
                                 Status.SKIPPED, "Nenhum endpoint GET/POST/PUT/PATCH configurado."))
    return findings


# ---------------------------------------------------------------------------
# API4:2023 - Unrestricted Resource Consumption
# ---------------------------------------------------------------------------

def test_api4_resource_consumption(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings = []
    if not cfg.endpoints:
        findings.append(Finding("API4:2023", "Unrestricted Resource Consumption", "-",
                                 Status.SKIPPED, "Nenhum endpoint configurado."))
        return findings

    target = cfg.endpoints[0]
    path = client.resolve_path(target)
    n = cfg.rate_limit_requests
    codes = []

    def fire(_):
        r = client.request(target.method, path, headers=cfg.auth_headers(), json_body=target.body)
        return r.status_code if r is not None else -1

    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, n)) as pool:
        codes = list(pool.map(fire, range(n)))
    elapsed = time.time() - start

    throttled = codes.count(429) > 0
    success = codes.count(200) + codes.count(201)
    if not throttled and success >= n * 0.8:
        findings.append(Finding(
            "API4:2023", "Unrestricted Resource Consumption", path, Status.VULNERABLE,
            f"{n} requisições em {elapsed:.1f}s não disparam rate limiting ({success} com sucesso, "
            f"0 bloqueadas com HTTP 429).",
            evidence=f"Distribuição de status: { {c: codes.count(c) for c in set(codes)} }",
            recommendation="Implemente rate limiting (ex.: token bucket) por IP/usuário/API key, "
                           "e limites de paginação/tamanho de payload.",
        ))
    else:
        findings.append(Finding("API4:2023", "Unrestricted Resource Consumption", path, Status.SAFE,
                                 f"Rate limiting aparentemente ativo (status: "
                                 f"{ {c: codes.count(c) for c in set(codes)} })."))

    # Teste de paginação sem limite (?limit=99999)
    resp = client.request(target.method, path, headers=cfg.auth_headers(), params={"limit": 999999, "page_size": 999999})
    data = safe_json(resp)
    if isinstance(data, list) and len(data) > 1000:
        findings.append(Finding(
            "API4:2023", "Unrestricted Resource Consumption", path, Status.VULNERABLE,
            f"Endpoint retornou {len(data)} itens ao solicitar limit=999999, sem limite de paginação no servidor.",
            recommendation="Defina um limite máximo de página no servidor, ignorando valores "
                           "absurdos enviados pelo cliente.",
        ))
    return findings


# ---------------------------------------------------------------------------
# API5:2023 - Broken Function Level Authorization
# ---------------------------------------------------------------------------

def test_api5_function_auth(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings = []
    admin_eps = [e for e in cfg.endpoints if e.privileged]
    if not admin_eps:
        findings.append(Finding("API5:2023", "Broken Function Level Authorization", "-",
                                 Status.SKIPPED, "Nenhum endpoint marcado como privileged=True."))
        return findings

    for ep in admin_eps:
        path = client.resolve_path(ep)
        # tenta com token comum (não-admin) ou sem token algum, se não houver secondary_token
        headers = cfg.auth_headers(cfg.secondary_token or cfg.primary_token)
        resp = client.request(ep.method, path, headers=headers, json_body=ep.body)
        if resp is None:
            findings.append(Finding("API5:2023", "Broken Function Level Authorization", path, Status.ERROR,
                                     "Falha de rede."))
            continue
        if resp.status_code < 300:
            findings.append(Finding(
                "API5:2023", "Broken Function Level Authorization", path, Status.VULNERABLE,
                "Bypass de autorização por função: usuário sem privilégios administrativos "
                "conseguiu executar uma ação/endpoint administrativo.",
                evidence=f"HTTP {resp.status_code} com token de usuário comum.",
                recommendation="Valide o papel/privilégio do usuário no backend para cada função "
                               "sensível, nunca apenas ocultando o botão/rota no frontend.",
            ))
        else:
            findings.append(Finding("API5:2023", "Broken Function Level Authorization", path, Status.SAFE,
                                     f"Acesso administrativo corretamente negado (HTTP {resp.status_code})."))

        # Bônus: troca de verbo HTTP (ex.: GET permitido, mas DELETE também aceito sem checagem)
        if ep.method.upper() != "DELETE":
            resp_del = client.request("DELETE", path, headers=headers)
            if resp_del is not None and resp_del.status_code < 300:
                findings.append(Finding(
                    "API5:2023", "Broken Function Level Authorization", path, Status.VULNERABLE,
                    "Verbo HTTP alternativo (DELETE) aceito sem checagem de autorização adequada.",
                    evidence=f"HTTP {resp_del.status_code} para DELETE {path}.",
                    recommendation="Aplique a mesma checagem de autorização para todos os verbos "
                                   "HTTP de uma rota, não apenas para o verbo 'esperado'.",
                ))
    return findings


# ---------------------------------------------------------------------------
# API6:2023 - Unrestricted Access to Sensitive Business Flows
# ---------------------------------------------------------------------------

def test_api6_business_flows(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    """Totalmente automático é difícil (depende de regra de negócio), então o
    teste é heurístico: repete uma ação de negócio N vezes rapidamente e
    verifica ausência de qualquer controle anti-automação (CAPTCHA, rate
    limit, verificação de dispositivo)."""
    findings = []
    candidates = [e for e in cfg.endpoints if e.method.upper() == "POST" and not e.privileged]
    if not candidates:
        findings.append(Finding("API6:2023", "Unrestricted Access to Sensitive Business Flows", "-",
                                 Status.SKIPPED, "Nenhum endpoint POST não-privilegiado configurado "
                                                  "para simular um fluxo de negócio (ex.: resgate de cupom, compra)."))
        return findings

    ep = candidates[0]
    path = client.resolve_path(ep)
    n = 15
    codes = []
    for i in range(n):
        resp = client.request("POST", path, headers=cfg.auth_headers(), json_body=ep.body)
        codes.append(resp.status_code if resp is not None else -1)
    anti_automation = any(c in (429, 403) for c in codes)
    if not anti_automation:
        findings.append(Finding(
            "API6:2023", "Unrestricted Access to Sensitive Business Flows", path, Status.INCONCLUSIVE,
            f"A ação foi repetida {n} vezes sem bloqueio (CAPTCHA/429/403). Isso É UM INDÍCIO, mas "
            "a confirmação de impacto real (ex.: esgotar estoque, abusar de cupons) requer "
            "revisão manual da regra de negócio.",
            evidence=f"Status retornados: {codes}",
            recommendation="Avalie fluxos de negócio sensíveis (compra, cupom, transferência) e "
                           "adicione controles como rate limiting dedicado, CAPTCHA, detecção de "
                           "automação e limites por usuário/dispositivo.",
        ))
    else:
        findings.append(Finding("API6:2023", "Unrestricted Access to Sensitive Business Flows", path,
                                 Status.SAFE, f"Algum controle anti-automação foi observado (status: {codes})."))
    return findings


# ---------------------------------------------------------------------------
# API7:2023 - Server Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------

def test_api7_ssrf(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings = []
    candidates = [e for e in cfg.endpoints if e.url_param_for_ssrf]
    if not candidates:
        findings.append(Finding("API7:2023", "Server Side Request Forgery", "-", Status.SKIPPED,
                                 "Nenhum endpoint com 'url_param_for_ssrf' configurado "
                                 "(ex.: webhook, fetch de imagem por URL, importação remota)."))
        return findings

    for ep in candidates:
        path = client.resolve_path(ep)
        # Além do nome de parâmetro configurado/descoberto, também envia os
        # nomes mais comuns de parâmetro de URL simultaneamente (como query
        # string E, se o endpoint aceita corpo, dentro do JSON também). Isso
        # evita falso-negativo quando o parâmetro foi 'adivinhado' por
        # descoberta automática e o nome exato não é conhecido de antemão.
        param_names = {ep.url_param_for_ssrf, *SSRF_PARAM_NAME_CANDIDATES}
        for probe in INTERNAL_PROBE_URLS:
            params = {name: probe for name in param_names}
            body = dict(ep.body or {})
            if ep.method.upper() in ("POST", "PUT", "PATCH"):
                body.update(params)
            t0 = time.time()
            resp = client.request(ep.method, path, headers=cfg.auth_headers(),
                                   json_body=body or None, params=params)
            dt = time.time() - t0
            if resp is None:
                continue
            body_text = (resp.text or "")[:500]
            suspicious = resp.status_code < 400 and (
                "root:" in body_text or "ami-id" in body_text.lower() or
                "instance-id" in body_text.lower() or dt > cfg.timeout * 0.9
            )
            if suspicious:
                findings.append(Finding(
                    "API7:2023", "Server Side Request Forgery", path, Status.VULNERABLE,
                    f"O servidor parece ter processado/encaminhado a requisição para um alvo "
                    f"interno/local ('{probe}').",
                    evidence=f"HTTP {resp.status_code}, tempo={dt:.2f}s, trecho da resposta: {body_text[:150]!r}",
                    recommendation="Valide e restrinja (allow-list) os domínios/IPs que a API pode "
                                   "buscar; bloqueie IPs privados/metadados de nuvem; desative "
                                   "redirecionamentos automáticos para esses destinos.",
                ))
            else:
                findings.append(Finding("API7:2023", "Server Side Request Forgery", path, Status.SAFE,
                                         f"Alvo interno '{probe}' não foi processado de forma suspeita "
                                         f"(HTTP {resp.status_code})."))
    return findings


# ---------------------------------------------------------------------------
# API8:2023 - Security Misconfiguration
# ---------------------------------------------------------------------------

COMMON_SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/debug", "/actuator/health", "/actuator/env",
    "/swagger.json", "/swagger-ui.html", "/openapi.json", "/.well-known/security.txt",
    "/server-status", "/trace", "/console",
]


def test_api8_misconfiguration(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings = []

    # 1) Cabeçalhos de segurança ausentes
    resp = client.request("GET", "/", headers=cfg.extra_headers)
    if resp is not None:
        missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
        if missing:
            findings.append(Finding(
                "API8:2023", "Security Misconfiguration", "/", Status.VULNERABLE,
                f"Cabeçalhos de segurança ausentes na resposta: {missing}.",
                recommendation="Configure os cabeçalhos HSTS, X-Content-Type-Options, "
                               "X-Frame-Options e Content-Security-Policy no servidor/gateway.",
            ))
        else:
            findings.append(Finding("API8:2023", "Security Misconfiguration", "/", Status.SAFE,
                                     "Principais cabeçalhos de segurança presentes."))

        server_hdr = resp.headers.get("Server", "")
        if server_hdr and re.search(r"\d+\.\d+", server_hdr):
            findings.append(Finding(
                "API8:2023", "Security Misconfiguration", "/", Status.VULNERABLE,
                f"Cabeçalho 'Server' expõe versão detalhada: '{server_hdr}'.",
                recommendation="Remova ou genéricalize o cabeçalho Server/X-Powered-By para não "
                               "vazar versão exata do software (facilita busca por CVEs conhecidos).",
            ))

        # CORS permissivo
        cors = resp.headers.get("Access-Control-Allow-Origin")
        if cors == "*":
            findings.append(Finding(
                "API8:2023", "Security Misconfiguration", "/", Status.VULNERABLE,
                "CORS configurado com 'Access-Control-Allow-Origin: *' — qualquer origem pode "
                "ler respostas da API via navegador.",
                recommendation="Restrinja Access-Control-Allow-Origin a uma allow-list de domínios "
                               "confiáveis, especialmente se a API usa cookies/credenciais.",
            ))
    else:
        findings.append(Finding("API8:2023", "Security Misconfiguration", "/", Status.ERROR,
                                 "Não foi possível conectar ao endpoint raiz para checar headers."))

    # 2) Erros verbosos (stack trace) ao enviar payload malformado
    for ep in cfg.endpoints[:3]:
        path = client.resolve_path(ep)
        resp = client.request(ep.method, path, headers=cfg.auth_headers(), json_body={"__malformed__": "' OR 1=1 -- \x00"})
        if resp is not None and resp.status_code >= 500:
            text = resp.text or ""
            leak_markers = ["Traceback", "Exception", "at java.", "stacktrace", "<?php", "Warning:", "Fatal error"]
            if any(m.lower() in text.lower() for m in leak_markers):
                findings.append(Finding(
                    "API8:2023", "Security Misconfiguration", path, Status.VULNERABLE,
                    "Erro 5xx retornou stack trace / detalhes internos no corpo da resposta.",
                    evidence=text[:300],
                    recommendation="Desative modo debug em produção; capture exceções e retorne "
                                   "mensagens de erro genéricas, registrando o detalhe apenas em logs internos.",
                ))

    # 3) Caminhos sensíveis expostos
    exposed = []
    for p in COMMON_SENSITIVE_PATHS:
        r = client.request("GET", p, headers=cfg.extra_headers)
        if r is not None and r.status_code == 200:
            exposed.append(p)
    if exposed:
        findings.append(Finding(
            "API8:2023", "Security Misconfiguration", ", ".join(exposed), Status.VULNERABLE,
            f"Caminhos sensíveis acessíveis publicamente: {exposed}.",
            recommendation="Remova/bloqueie acesso externo a arquivos de configuração, consoles de "
                           "debug, docs internas e endpoints de administração do framework.",
        ))
    else:
        findings.append(Finding("API8:2023", "Security Misconfiguration",
                                 "/".join(COMMON_SENSITIVE_PATHS[:3]) + " ...", Status.SAFE,
                                 "Nenhum dos caminhos sensíveis testados está publicamente acessível."))
    return findings


# ---------------------------------------------------------------------------
# API9:2023 - Improper Inventory Management
# ---------------------------------------------------------------------------

def test_api9_inventory(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    findings = []
    versions_to_try = ["v1", "v2", "v3", "beta", "internal", "old", "legacy", "test", "staging"]
    base_path = cfg.endpoints[0].path if cfg.endpoints else "/api/"
    base_resource = re.sub(r"^/api/v\d+/?", "/", base_path)
    base_resource = re.sub(r"\{.*?\}", "1", base_resource)

    discovered = []
    for v in versions_to_try:
        if cfg.documented_version and v == cfg.documented_version:
            continue
        candidate = f"/api/{v}{base_resource}"
        resp = client.request("GET", candidate, headers=cfg.auth_headers())
        if resp is not None and resp.status_code not in (404, 410):
            discovered.append((candidate, resp.status_code))

    if discovered:
        findings.append(Finding(
            "API9:2023", "Improper Inventory Management", str([d[0] for d in discovered]), Status.VULNERABLE,
            f"Versões/ambientes não documentados da API respondem (possível 'API fantasma'): {discovered}.",
            recommendation="Mantenha um inventário atualizado de todas as versões/ambientes "
                           "publicados; desative definitivamente versões antigas em vez de deixá-las "
                           "ativas e esquecidas.",
        ))
    else:
        findings.append(Finding("API9:2023", "Improper Inventory Management", base_resource, Status.SAFE,
                                 "Nenhuma versão alternativa não-documentada respondeu com sucesso."))

    # Documentação exposta (pode ou não ser problema, dependendo do contexto)
    for doc_path in ["/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs"]:
        resp = client.request("GET", doc_path, headers=cfg.extra_headers)
        if resp is not None and resp.status_code == 200:
            findings.append(Finding(
                "API9:2023", "Improper Inventory Management", doc_path, Status.INCONCLUSIVE,
                "Documentação OpenAPI/Swagger publicamente acessível. Pode ser intencional (API "
                "pública) ou um vazamento de endpoints internos — revise manualmente o conteúdo.",
                recommendation="Garanta que a documentação exposta publicamente não revele "
                               "endpoints internos/administrativos não destinados a consumidores externos.",
            ))
    return findings


# ---------------------------------------------------------------------------
# API10:2023 - Unsafe Consumption of APIs
# ---------------------------------------------------------------------------

def test_api10_unsafe_consumption(client: HttpClient, cfg: ScanConfig) -> List[Finding]:
    """Difícil de automatizar totalmente sem conhecer as integrações de
    terceiros da aplicação. Este módulo faz uma checagem heurística de
    endpoints que parecem repassar/consumir dados de serviços externos."""
    findings = []
    suspicious_names = ["webhook", "callback", "import", "sync", "integration", "external", "proxy"]
    candidates = [e for e in cfg.endpoints if any(s in e.path.lower() for s in suspicious_names)]
    if not candidates:
        findings.append(Finding(
            "API10:2023", "Unsafe Consumption of APIs", "-", Status.SKIPPED,
            "Nenhum endpoint com nome sugestivo de integração externa (webhook/callback/import/sync) "
            "foi encontrado na configuração. Este item geralmente requer revisão manual de código "
            "e arquitetura (quais APIs de terceiros a aplicação consome e como valida as respostas).",
        ))
        return findings

    for ep in candidates:
        path = client.resolve_path(ep)
        # Envia um payload com tipos inesperados para ver se a app valida/sanitiza
        malicious_payload = {
            "data": "<script>alert(1)</script>",
            "url": "javascript:alert(1)",
            "amount": "not_a_number",
            "nested": {"__proto__": {"polluted": True}},
        }
        resp = client.request(ep.method, path, headers=cfg.auth_headers(), json_body=malicious_payload)
        if resp is not None and resp.status_code < 300:
            findings.append(Finding(
                "API10:2023", "Unsafe Consumption of APIs", path, Status.INCONCLUSIVE,
                "O endpoint de integração aceitou payload com tipos/valores inesperados sem "
                "validação aparente (HTTP < 300). Revise manualmente se os dados recebidos de "
                "serviços externos passam por validação de schema antes do uso.",
                evidence=f"HTTP {resp.status_code}",
                recommendation="Valide e sanitize toda resposta recebida de APIs de terceiros "
                               "(schema validation), trate-as como entrada não confiável, "
                               "e use timeouts/circuit breakers nas chamadas de saída.",
            ))
        elif resp is not None:
            findings.append(Finding("API10:2023", "Unsafe Consumption of APIs", path, Status.SAFE,
                                     f"Payload malformado rejeitado (HTTP {resp.status_code})."))
    return findings


# ---------------------------------------------------------------------------
# Registro central dos testes
# ---------------------------------------------------------------------------

TEST_REGISTRY = {
    "API1": ("API1:2023", "Broken Object Level Authorization", test_api1_bola),
    "API2": ("API2:2023", "Broken Authentication", test_api2_broken_auth),
    "API3": ("API3:2023", "Broken Object Property Level Authorization", test_api3_property_auth),
    "API4": ("API4:2023", "Unrestricted Resource Consumption", test_api4_resource_consumption),
    "API5": ("API5:2023", "Broken Function Level Authorization", test_api5_function_auth),
    "API6": ("API6:2023", "Unrestricted Access to Sensitive Business Flows", test_api6_business_flows),
    "API7": ("API7:2023", "Server Side Request Forgery", test_api7_ssrf),
    "API8": ("API8:2023", "Security Misconfiguration", test_api8_misconfiguration),
    "API9": ("API9:2023", "Improper Inventory Management", test_api9_inventory),
    "API10": ("API10:2023", "Unsafe Consumption of APIs", test_api10_unsafe_consumption),
}


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: str) -> ScanConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    endpoints = [Endpoint(**e) for e in raw.get("endpoints", [])]
    raw2 = dict(raw)
    raw2["endpoints"] = endpoints
    return ScanConfig(**raw2)


def config_to_dict(cfg: ScanConfig) -> dict:
    """Serializa um ScanConfig (com seus Endpoints) de volta para um dict
    pronto para json.dump — espelha exatamente o formato aceito por
    load_config(), permitindo salvar uma configuração gerada automaticamente
    para o usuário inspecionar/editar depois."""
    d = asdict(cfg)
    return d


def save_config(cfg: ScanConfig, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config_to_dict(cfg), f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Auto-configuração a partir de uma URL (descoberta automática de endpoints)
# ---------------------------------------------------------------------------
#
# Objetivo: o usuário informa SOMENTE a URL base da API (e, opcionalmente,
# token(s) de autenticação e/ou usuário+senha de login). A partir disso o
# scanner tenta:
#   1) localizar e interpretar uma especificação OpenAPI/Swagger publicada;
#   2) se não encontrar, sondar (probe) uma lista de padrões de rota REST
#      comuns para descobrir endpoints "na unha" (heurística);
#   3) localizar um endpoint de login comum e, se usuário/senha forem
#      informados, autenticar automaticamente para obter um token;
# e then monta um ScanConfig completo — que é salvo em config.json para que
# o usuário possa revisar/ajustar manualmente antes de rodar de novo, e que
# já é usado imediatamente para a varredura atual.

OPENAPI_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/api/openapi.json", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/.well-known/openapi.json",
]

RESOURCE_CANDIDATES = [
    "users", "user", "accounts", "account", "profile", "me",
    "products", "product", "items", "item", "orders", "order",
    "customers", "customer", "posts", "post", "comments",
    "admin/users", "admin", "webhooks/import", "webhooks",
    "integration/sync", "integrations",
]

PREFIX_CANDIDATES = ["/api/v1", "/api/v2", "/api", ""]

LOGIN_PATH_CANDIDATES = [
    "/api/login", "/api/auth/login", "/api/v1/login", "/api/v1/auth/login",
    "/login", "/auth/login", "/api/token", "/api/v1/token",
]

TOKEN_RESPONSE_KEYS = ["token", "access_token", "jwt", "id_token", "authToken"]

SSRF_PARAM_NAME_CANDIDATES = ["url", "target_url", "webhook_url", "callback_url", "uri"]


def _probe(client: HttpClient, method: str, path: str, headers: dict,
           json_body: Optional[dict] = None) -> Optional[requests.Response]:
    try:
        return client.request(method, path, headers=headers, json_body=json_body)
    except Exception:
        return None


def try_fetch_openapi_spec(client: HttpClient, headers: dict) -> Optional[dict]:
    """Tenta localizar uma especificação OpenAPI/Swagger (JSON) publicada
    em caminhos comuns. Retorna o dict da especificação, ou None."""
    for path in OPENAPI_SPEC_PATHS:
        resp = _probe(client, "GET", path, headers)
        if resp is None or resp.status_code != 200:
            continue
        data = safe_json(resp)
        if isinstance(data, dict) and ("paths" in data) and ("swagger" in data or "openapi" in data):
            return data
    return None


def endpoints_from_openapi(spec: dict) -> List[Endpoint]:
    """Converte as rotas de uma especificação OpenAPI/Swagger em Endpoints
    do scanner. O formato de parâmetro de caminho do OpenAPI ({id}) já é
    idêntico ao usado internamente pelo scanner."""
    endpoints: List[Endpoint] = []
    paths = spec.get("paths", {})
    for raw_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        path_params = re.findall(r"\{(\w+)\}", raw_path)
        id_param = path_params[0] if path_params else None
        lower_path = raw_path.lower()
        privileged = "admin" in lower_path
        ssrf_param = None
        for cand in SSRF_PARAM_NAME_CANDIDATES:
            if cand in lower_path or any(
                k in lower_path for k in ("webhook", "import", "callback", "fetch", "proxy")
            ):
                ssrf_param = cand
                break
        for verb, details in methods.items():
            verb_up = verb.upper()
            if verb_up not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            sample_body = None
            if verb_up in ("POST", "PUT", "PATCH"):
                sample_body = {}
                if isinstance(details, dict):
                    for param in details.get("parameters", []):
                        if isinstance(param, dict) and param.get("in") == "body":
                            sample_body = {"example": "value"}
            endpoints.append(Endpoint(
                path=raw_path,
                method=verb_up,
                id_param=id_param,
                sample_id="1" if id_param else None,
                alt_id="2" if id_param else None,
                auth_required=True,
                body=sample_body,
                description=(details.get("summary") if isinstance(details, dict) else "") or "",
                privileged=privileged,
                url_param_for_ssrf=ssrf_param if verb_up in ("GET", "POST") else None,
            ))
    return endpoints


def heuristic_discover_endpoints(client: HttpClient, headers: dict) -> List[Endpoint]:
    """Quando não há especificação OpenAPI publicada, sonda uma lista de
    padrões de rota REST comuns (prefixo + recurso [+ /{id}]) e mantém
    apenas os que o servidor reconhece (ou seja, não respondem 404/erro de
    rede). Qualquer resposta que não seja 404 é considerada 'rota existe',
    mesmo que retorne 401/403 (protegida) — o objetivo aqui é mapear a
    superfície, não validar permissões."""
    discovered: List[Endpoint] = []
    seen_paths = set()
    for prefix in PREFIX_CANDIDATES:
        for resource in RESOURCE_CANDIDATES:
            list_path = f"{prefix}/{resource}".replace("//", "/")
            if list_path in seen_paths:
                continue

            # Sonda a listagem (ex.: /api/v1/users) E o detalhe (ex.:
            # /api/v1/users/1) de forma independente: muitas APIs só expõem
            # uma das duas rotas (ex.: só o detalhe por ID, sem endpoint de
            # listagem), então não dá para condicionar uma à outra.
            resp_list = _probe(client, "GET", list_path, headers)
            list_exists = resp_list is not None and resp_list.status_code not in (404, 410)

            detail_path = f"{list_path}/1"
            resp_detail = _probe(client, "GET", detail_path, headers)
            has_detail = resp_detail is not None and resp_detail.status_code not in (404, 410)

            if not list_exists and not has_detail:
                continue
            seen_paths.add(list_path)
            privileged = "admin" in resource
            is_integration = any(k in resource for k in ("webhook", "import", "integration", "sync"))

            if has_detail:
                base_tpl = f"{list_path}/{{id}}"
                discovered.append(Endpoint(
                    path=base_tpl, method="GET", id_param="id", sample_id="1", alt_id="2",
                    auth_required=True, privileged=privileged,
                    description=f"Descoberto automaticamente a partir de {detail_path}",
                ))
                discovered.append(Endpoint(
                    path=base_tpl, method="PUT", id_param="id", sample_id="1",
                    auth_required=True, body={"name": "teste_autoconfig"}, privileged=privileged,
                    description="Teste de mass assignment (gerado automaticamente)",
                ))
            else:
                ssrf_param = SSRF_PARAM_NAME_CANDIDATES[0] if is_integration else None
                discovered.append(Endpoint(
                    path=list_path,
                    method="POST" if is_integration else "GET",
                    auth_required=True,
                    privileged=privileged,
                    body={"probe": "autoconfig"} if is_integration else None,
                    url_param_for_ssrf=ssrf_param,
                    description=f"Descoberto automaticamente a partir de {list_path}",
                ))
    return discovered


def discover_login_endpoint(client: HttpClient, headers: dict) -> Optional[str]:
    for path in LOGIN_PATH_CANDIDATES:
        resp = _probe(client, "POST", path, headers, json_body={"username": "probe", "password": "probe"})
        if resp is not None and resp.status_code not in (404, 410):
            return path
    return None


def attempt_auto_login(client: HttpClient, login_path: str, username: str, password: str,
                        headers: dict) -> Optional[str]:
    """Tenta autenticar automaticamente no endpoint de login descoberto,
    usando credenciais fornecidas pelo usuário, e extrai o token do corpo
    da resposta (chaves comuns: token, access_token, jwt, id_token)."""
    for body in ({"username": username, "password": password},
                 {"email": username, "password": password}):
        resp = _probe(client, "POST", login_path, headers, json_body=body)
        data = safe_json(resp)
        if resp is not None and resp.status_code < 300 and isinstance(data, dict):
            for key in TOKEN_RESPONSE_KEYS:
                if key in data and isinstance(data[key], str):
                    return data[key]
    return None


def build_config_from_url(base_url: str, primary_token: str = "", secondary_token: str = "",
                           username: Optional[str] = None, password: Optional[str] = None,
                           verify_ssl: bool = True, proxy: Optional[str] = None,
                           timeout: float = 8.0) -> ScanConfig:
    """Monta um ScanConfig completo a partir de apenas uma URL base: esta é
    a função central do modo 'só a URL' — ela incorpora/gera o config.json
    automaticamente em vez de exigir que o usuário o escreva à mão."""
    cfg = ScanConfig(
        base_url=base_url if base_url.endswith("/") else base_url + "/",
        primary_token=primary_token,
        secondary_token=secondary_token,
        verify_ssl=verify_ssl,
        proxy=proxy,
        timeout=timeout,
    )
    client = HttpClient(cfg)
    probe_headers = cfg.auth_headers()

    print(">>> Procurando especificação OpenAPI/Swagger publicada...")
    spec = try_fetch_openapi_spec(client, probe_headers)
    if spec:
        endpoints = endpoints_from_openapi(spec)
        print(f"    ✓ Especificação encontrada! {len(endpoints)} rota(s)/verbo(s) importado(s).")
    else:
        print("    Nenhuma especificação encontrada. Sondando rotas REST comuns (heurística)...")
        endpoints = heuristic_discover_endpoints(client, probe_headers)
        print(f"    ✓ {len(endpoints)} endpoint(s) candidato(s) descoberto(s) por heurística.")

    print(">>> Procurando endpoint de login (para teste de força bruta / API2)...")
    login_path = discover_login_endpoint(client, probe_headers)
    if login_path:
        print(f"    ✓ Possível endpoint de login encontrado: {login_path}")
        cfg.login_endpoint = login_path
        cfg.login_body_template = {"username": "admin", "password": "{password}"}
        if username and password and not primary_token:
            print("    Tentando autenticação automática com as credenciais fornecidas...")
            token = attempt_auto_login(client, login_path, username, password, probe_headers)
            if token:
                print("    ✓ Login automático bem-sucedido, token obtido.")
                cfg.primary_token = token
            else:
                print("    ✗ Não foi possível obter um token automaticamente com essas credenciais.")
    else:
        print("    Nenhum endpoint de login óbvio encontrado (configure manualmente se necessário).")

    # Tenta identificar a versão "oficial" da API a partir do primeiro
    # endpoint descoberto (ex.: /api/v1/...) para que o teste de inventário
    # (API9) não acuse a própria versão documentada como "fantasma".
    documented_version = None
    for ep in endpoints:
        m = re.search(r"/api/(v\d+)/", ep.path)
        if m:
            documented_version = m.group(1)
            break
    cfg.documented_version = documented_version
    cfg.endpoints = endpoints
    return cfg


def example_config_dict() -> dict:
    return {
        "base_url": "http://127.0.0.1:5000",
        "primary_token": "TOKEN_DO_USUARIO_1",
        "secondary_token": "TOKEN_DO_USUARIO_2",
        "auth_header": "Authorization",
        "auth_scheme": "Bearer",
        "extra_headers": {},
        "login_endpoint": "/api/login",
        "login_body_template": {"username": "admin", "password": "{password}"},
        "rate_limit_requests": 40,
        "rate_limit_window_seconds": 5.0,
        "timeout": 8.0,
        "verify_ssl": True,
        "proxy": None,
        "documented_version": "v1",
        "endpoints": [
            {
                "path": "/api/v1/users/{id}",
                "method": "GET",
                "id_param": "id",
                "sample_id": "2",
                "alt_id": "1",
                "auth_required": True,
                "sensitive_fields": ["email"],
                "description": "Perfil de usuário por ID",
            },
            {
                "path": "/api/v1/users/{id}",
                "method": "PUT",
                "id_param": "id",
                "sample_id": "2",
                "auth_required": True,
                "body": {"name": "Teste"},
                "description": "Atualização de perfil (teste de mass assignment)",
            },
            {
                "path": "/api/v1/admin/users",
                "method": "GET",
                "auth_required": True,
                "privileged": True,
                "description": "Listagem administrativa de usuários",
            },
            {
                "path": "/api/v1/webhooks/import",
                "method": "POST",
                "auth_required": True,
                "url_param_for_ssrf": "target_url",
                "body": {"target_url": "http://example.com"},
                "description": "Importação remota de dados (candidato a SSRF)",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Relatório / saída
# ---------------------------------------------------------------------------

STATUS_COLOR = {
    Status.VULNERABLE: Fore.RED if COLOR_OK else "",
    Status.SAFE: Fore.GREEN if COLOR_OK else "",
    Status.INCONCLUSIVE: Fore.YELLOW if COLOR_OK else "",
    Status.SKIPPED: Fore.CYAN if COLOR_OK else "",
    Status.ERROR: Fore.MAGENTA if COLOR_OK else "",
}
RESET = Style.RESET_ALL if COLOR_OK else ""


def print_finding(f: Finding) -> None:
    color = STATUS_COLOR.get(f.status, "")
    print(f"{color}[{f.status.value:^12}]{RESET} {f.api_id} - {f.title}")
    print(f"    Endpoint : {f.endpoint}")
    print(f"    Detalhe  : {f.detail}")
    if f.evidence:
        print(f"    Evidência: {f.evidence}")
    if f.recommendation:
        print(f"    Correção : {f.recommendation}")
    print("-" * 78)


def summarize(findings: List[Finding]) -> Dict[str, int]:
    summary = {s.value: 0 for s in Status}
    for f in findings:
        summary[f.status.value] += 1
    return summary


def print_summary(findings: List[Finding]) -> None:
    summary = summarize(findings)
    print("\n" + "=" * 78)
    print(" RESUMO DO SCAN ".center(78, "="))
    print("=" * 78)
    for status, count in summary.items():
        print(f"  {status:<14}: {count}")
    vulnerable = [f for f in findings if f.status == Status.VULNERABLE]
    if vulnerable:
        print(f"\n{Fore.RED if COLOR_OK else ''}⚠ {len(vulnerable)} vulnerabilidade(s) confirmada(s) "
              f"(bypass bem-sucedido):{RESET}")
        for f in vulnerable:
            print(f"   - {f.api_id} ({f.title}) em {f.endpoint}")
    else:
        print(f"\n{Fore.GREEN if COLOR_OK else ''}✓ Nenhuma vulnerabilidade confirmada nos testes executados.{RESET}")
    print("=" * 78)


def export_json(findings: List[Finding], out_path: str) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def export_html(findings: List[Finding], out_path: str, target: str) -> None:
    summary = summarize(findings)
    rows = []
    badge_class = {
        Status.VULNERABLE.value: "bad", Status.SAFE.value: "ok",
        Status.INCONCLUSIVE.value: "warn", Status.SKIPPED.value: "skip", Status.ERROR.value: "err",
    }
    for f in findings:
        rows.append(f"""
        <tr>
          <td>{f.api_id}</td>
          <td>{f.title}</td>
          <td><code>{f.endpoint}</code></td>
          <td><span class="badge {badge_class.get(f.status.value, '')}">{f.status.value}</span></td>
          <td>{f.detail}</td>
          <td><small>{f.evidence}</small></td>
          <td><small>{f.recommendation}</small></td>
        </tr>""")
    html = f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8">
<title>Relatório OWASP API Security Top 10 — {target}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background:#0b0f14; color:#e6e6e6; }}
h1 {{ color:#fff; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ border: 1px solid #2a2f36; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background:#161b22; }}
tr:nth-child(even) {{ background:#11161c; }}
.badge {{ padding: 2px 8px; border-radius: 10px; font-weight: bold; font-size: 0.75rem; }}
.badge.bad {{ background:#5c1a1a; color:#ff8080; }}
.badge.ok {{ background:#1a5c2a; color:#80ff9a; }}
.badge.warn {{ background:#5c4a1a; color:#ffd480; }}
.badge.skip {{ background:#1a3a5c; color:#80c7ff; }}
.badge.err {{ background:#3a1a5c; color:#c780ff; }}
.summary span {{ margin-right: 1.5rem; }}
code {{ color:#9cdcfe; }}
</style></head>
<body>
<h1>Relatório — OWASP API Security Top 10 (2023)</h1>
<p>Alvo: <code>{target}</code> &middot; Gerado em: {datetime.now(timezone.utc).isoformat()}</p>
<div class="summary">
{''.join(f'<span><b>{k}:</b> {v}</span>' for k, v in summary.items())}
</div>
<table>
<thead><tr><th>Item</th><th>Categoria</th><th>Endpoint</th><th>Status</th><th>Detalhe</th><th>Evidência</th><th>Correção</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body></html>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


# ---------------------------------------------------------------------------
# Execução dos testes
# ---------------------------------------------------------------------------

def run_tests(cfg: ScanConfig, test_keys: List[str]) -> List[Finding]:
    client = HttpClient(cfg)
    all_findings: List[Finding] = []
    for key in test_keys:
        api_id, title, func = TEST_REGISTRY[key]
        print(f"\n>>> Executando {api_id} - {title} ...")
        try:
            results = func(client, cfg)
        except Exception as exc:  # nunca deixa o scanner inteiro cair por causa de 1 módulo
            results = [Finding(api_id, title, "-", Status.ERROR, f"Exceção não tratada no módulo: {exc!r}")]
        for r in results:
            print_finding(r)
        all_findings.extend(results)
    return all_findings


# ---------------------------------------------------------------------------
# Termo de uso / confirmação de autorização
# ---------------------------------------------------------------------------

DISCLAIMER = """
############################################################################
#  OWASP API SECURITY TOP 10 - SCANNER DE BYPASS ATIVO                    #
#  Esta ferramenta realiza tentativas REAIS de bypass de autenticação,    #
#  autorização, rate limiting e outras proteções.                        #
#                                                                          #
#  USE SOMENTE em sistemas próprios ou com autorização EXPLÍCITA e por    #
#  escrito do responsável pelo sistema. O uso não autorizado pode         #
#  configurar crime (ex.: Lei 12.737/2012 no Brasil) e violação de        #
#  termos de serviço.                                                     #
############################################################################
"""


def confirm_authorization(assume_yes: bool = False) -> bool:
    print(DISCLAIMER)
    if assume_yes:
        return True
    resp = input("Você possui autorização explícita para testar este alvo? (digite 'CONFIRMO' para prosseguir): ")
    return resp.strip().upper() == "CONFIRMO"


# ---------------------------------------------------------------------------
# Menu interativo
# ---------------------------------------------------------------------------

def pause():
    input("\nPressione ENTER para continuar...")


def menu_header(title: str) -> None:
    os.system("cls" if os.name == "nt" else "clear") if sys.stdout.isatty() else None
    print("=" * 78)
    print(f" {title} ".center(78, "="))
    print("=" * 78)


def menu_listar_itens():
    menu_header("OWASP API Security Top 10 (2023)")
    for key, (api_id, title, _) in TEST_REGISTRY.items():
        print(f"  {key:<6} {api_id:<12} {title}")
    pause()


def menu_gerar_config_por_url() -> Optional[ScanConfig]:
    """Opção principal e recomendada: o usuário informa apenas a URL da API
    e o scanner descobre os endpoints e monta (e salva) o config.json
    sozinho, sem que o usuário precise escrevê-lo manualmente."""
    menu_header("Gerar configuração automaticamente a partir de uma URL")
    print("Informe apenas a URL da API alvo. O scanner vai tentar descobrir")
    print("os endpoints sozinho (via OpenAPI/Swagger ou sondagem de rotas comuns)")
    print("e gerar o config.json para você.\n")
    base_url = input("URL base da API (ex.: http://127.0.0.1:5000): ").strip()
    if not base_url:
        print("✗ URL não pode ser vazia.")
        pause()
        return None
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "http://" + base_url

    token = input("Token de autenticação do usuário principal (ENTER para nenhum): ").strip()
    secondary_token = input("Token de um segundo usuário, p/ teste de IDOR cruzado (ENTER p/ pular): ").strip()
    username = input("Usuário p/ tentar login automático (ENTER p/ pular): ").strip() or None
    password = None
    if username:
        password = input("Senha correspondente: ").strip() or None
    verify_raw = input("Verificar certificado TLS? (S/n) [S]: ").strip().lower()
    verify_ssl = verify_raw not in ("n", "nao", "não")

    print()
    try:
        cfg = build_config_from_url(
            base_url, primary_token=token, secondary_token=secondary_token,
            username=username, password=password, verify_ssl=verify_ssl,
        )
    except Exception as exc:
        print(f"\n✗ Erro durante a descoberta automática: {exc!r}")
        pause()
        return None

    print(f"\n✓ Descoberta concluída: {len(cfg.endpoints)} endpoint(s) candidato(s).")
    for ep in cfg.endpoints:
        marca = " [ADMIN]" if ep.privileged else ""
        print(f"    - {ep.method:<6} {ep.path}{marca}")
    if not cfg.endpoints:
        print("    (nenhum endpoint descoberto — talvez a API exija autenticação para sondagem, "
              "ou use padrões de rota não cobertos pela heurística. Você pode complementar "
              "manualmente o config.json gerado.)")

    save_path = input("\nSalvar esta configuração em [config.json]: ").strip() or "config.json"
    try:
        save_config(cfg, save_path)
        print(f"✓ Configuração salva em '{save_path}' — edite esse arquivo manualmente se quiser "
              f"ajustar/completar endpoints antes de rodar de novo (opção 'Carregar configuração').")
    except Exception as exc:
        print(f"⚠ Não foi possível salvar o config em '{save_path}': {exc!r}")
    pause()
    return cfg


def menu_criar_config_exemplo():
    menu_header("Gerar config.json de exemplo")
    path = input("Nome do arquivo a criar [config.json]: ").strip() or "config.json"
    if os.path.exists(path):
        if input(f"'{path}' já existe. Sobrescrever? (s/N): ").strip().lower() != "s":
            return
    with open(path, "w", encoding="utf-8") as f:
        json.dump(example_config_dict(), f, ensure_ascii=False, indent=2)
    print(f"\n✓ Arquivo '{path}' criado. Edite-o com os dados reais da sua API antes de rodar os testes.")
    pause()


def menu_carregar_config() -> Optional[ScanConfig]:
    menu_header("Carregar configuração")
    path = input("Caminho do arquivo config.json [config.json]: ").strip() or "config.json"
    if not os.path.exists(path):
        print(f"✗ Arquivo '{path}' não encontrado. Use a opção de gerar um config de exemplo primeiro.")
        pause()
        return None
    try:
        cfg = load_config(path)
        print(f"✓ Configuração carregada: base_url={cfg.base_url}, {len(cfg.endpoints)} endpoint(s).")
        pause()
        return cfg
    except Exception as exc:
        print(f"✗ Erro ao carregar config: {exc!r}")
        pause()
        return None


def menu_rodar_testes(cfg: Optional[ScanConfig], keys: List[str]):
    if cfg is None:
        print("✗ Nenhuma configuração carregada. Carregue um config.json primeiro (opção 2).")
        pause()
        return
    if not confirm_authorization():
        print("Operação cancelada: autorização não confirmada.")
        pause()
        return
    findings = run_tests(cfg, keys)
    print_summary(findings)
    export_choice = input("\nExportar relatório? (json/html/n): ").strip().lower()
    if export_choice == "json":
        out = input("Nome do arquivo [relatorio.json]: ").strip() or "relatorio.json"
        export_json(findings, out)
        print(f"✓ Relatório salvo em {out}")
    elif export_choice == "html":
        out = input("Nome do arquivo [relatorio.html]: ").strip() or "relatorio.html"
        export_html(findings, out, cfg.base_url)
        print(f"✓ Relatório salvo em {out}")
    pause()
    return findings


def menu_exportar(cfg: Optional[ScanConfig], last_findings: List[Finding]):
    menu_header("Exportar relatório")
    if not last_findings:
        print("Nenhum resultado em memória. Rode os testes primeiro.")
        pause()
        return
    fmt = input("Formato (json/html) [html]: ").strip().lower() or "html"
    out = input(f"Nome do arquivo [relatorio.{fmt}]: ").strip() or f"relatorio.{fmt}"
    if fmt == "json":
        export_json(last_findings, out)
    else:
        export_html(last_findings, out, cfg.base_url if cfg else "desconhecido")
    print(f"✓ Relatório salvo em {out}")
    pause()


def interactive_menu():
    cfg: Optional[ScanConfig] = None
    last_findings: List[Finding] = []

    while True:
        menu_header("OWASP API SECURITY TOP 10 - MENU PRINCIPAL")
        status_cfg = cfg.base_url if cfg else "(nenhuma configuração carregada)"
        print(f"Alvo atual: {status_cfg}\n")
        print("  1) ⭐ Gerar configuração a partir de uma URL (recomendado — só a URL)")
        print("  2) Ver os 10 itens do OWASP API Security Top 10")
        print("  3) Carregar configuração já existente (config.json)")
        print("  4) Gerar config.json de exemplo em branco (edição manual)")
        print("  5) Executar TODOS os testes (bypass completo)")
        print("  6) Executar um teste específico (API1-API10)")
        print("  7) Exportar último relatório (JSON/HTML)")
        print("  8) Ajuda / termo de uso autorizado")
        print("  0) Sair")
        choice = input("\nEscolha uma opção: ").strip()

        if choice == "1":
            generated = menu_gerar_config_por_url()
            if generated:
                cfg = generated
        elif choice == "2":
            menu_listar_itens()
        elif choice == "3":
            loaded = menu_carregar_config()
            if loaded:
                cfg = loaded
        elif choice == "4":
            menu_criar_config_exemplo()
        elif choice == "5":
            result = menu_rodar_testes(cfg, list(TEST_REGISTRY.keys()))
            if result:
                last_findings = result
        elif choice == "6":
            menu_header("Selecionar teste específico")
            for key, (api_id, title, _) in TEST_REGISTRY.items():
                print(f"  {key:<6} {api_id:<12} {title}")
            key = input("\nDigite o código (ex.: API1): ").strip().upper()
            if key in TEST_REGISTRY:
                result = menu_rodar_testes(cfg, [key])
                if result:
                    last_findings = result
            else:
                print("✗ Código inválido.")
                pause()
        elif choice == "7":
            menu_exportar(cfg, last_findings)
        elif choice == "8":
            menu_header("Ajuda")
            print(DISCLAIMER)
            print("""
Fluxo recomendado (mais rápido):
  1. Opção 1: informe apenas a URL da sua API de teste/laboratório
     (e token(s)/credenciais, se tiver). O scanner descobre os endpoints
     sozinho e já gera/salva o config.json por trás dos panos.
  2. Opção 5 (todos) ou 6 (específico): execute os testes de bypass.
  3. Opção 7: exporte o relatório em HTML para apresentar o resultado.

Fluxo manual (mais preciso, quando a descoberta automática não for suficiente):
  1. Opção 4: gere um config.json de exemplo em branco.
  2. Edite-o manualmente com os endpoints exatos, tokens de 2 usuários
     distintos e demais detalhes da sua API.
  3. Opção 3: carregue o config.json editado.
  4. Opções 5/6 e 7, como acima.

Modo não-interativo (CLI), útil para scripts/CI:
  python3 owasp_api_top10.py --url http://alvo.com --all --yes --output rel.html
  python3 owasp_api_top10.py --config config.json --test API1 API5 --yes
""")
            pause()
        elif choice == "0":
            print("Saindo. Até mais!")
            break
        else:
            print("✗ Opção inválida.")
            pause()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Scanner automatizado do OWASP API Security Top 10 (2023), com tentativas de bypass.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemplos:\n"
               "  python3 owasp_api_top10.py                          # abre o menu interativo\n"
               "  python3 owasp_api_top10.py --url http://alvo.com --all --yes\n"
               "      # basta a URL: o config.json é gerado automaticamente por descoberta\n"
               "  python3 owasp_api_top10.py --url http://alvo.com --token SEU_TOKEN --all --yes\n"
               "  python3 owasp_api_top10.py --init-config            # cria config.json de exemplo (manual)\n"
               "  python3 owasp_api_top10.py --config config.json --all --yes\n"
               "  python3 owasp_api_top10.py --config config.json --test API1 API2 API8 --output rel.html\n",
    )
    p.add_argument("--url", help="URL base da API alvo. Basta isso: o scanner descobre os "
                                  "endpoints automaticamente e gera/usa o config.json por você.")
    p.add_argument("--token", default="", help="Token de autenticação (usuário principal), usado com --url.")
    p.add_argument("--secondary-token", default="", help="Token de um segundo usuário (para IDOR cruzado), usado com --url.")
    p.add_argument("--username", help="Usuário para tentar login automático no endpoint de login descoberto (com --url).")
    p.add_argument("--password", help="Senha para tentar login automático (com --url).")
    p.add_argument("--save-config", default="config.json",
                    help="Caminho onde salvar o config.json gerado a partir de --url (padrão: config.json).")
    p.add_argument("--no-verify-ssl", action="store_true", help="Desativa verificação de certificado TLS (uso em lab).")
    p.add_argument("--config", help="Caminho para um arquivo de configuração JSON já existente "
                                      "(alternativa a --url, para quem quer editar manualmente).")
    p.add_argument("--all", action="store_true", help="Executa todos os 10 testes.")
    p.add_argument("--test", nargs="+", choices=list(TEST_REGISTRY.keys()),
                    help="Executa teste(s) específico(s), ex.: --test API1 API5")
    p.add_argument("--output", help="Caminho do relatório de saída (.json ou .html).")
    p.add_argument("--yes", action="store_true",
                    help="Confirma automaticamente a autorização de uso (use com responsabilidade).")
    p.add_argument("--init-config", action="store_true",
                    help="Gera um config.json de exemplo (manual) e sai.")
    p.add_argument("--menu", action="store_true", help="Força a abertura do menu interativo.")
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.init_config:
        path = "config.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(example_config_dict(), f, ensure_ascii=False, indent=2)
        print(f"✓ Config de exemplo criado em {path}")
        return

    # Sem argumentos relevantes -> menu interativo
    if args.menu or (not args.config and not args.url and not args.all and not args.test):
        interactive_menu()
        return

    if args.config:
        try:
            cfg = load_config(args.config)
        except Exception as exc:
            print(f"✗ Erro ao carregar configuração '{args.config}': {exc!r}")
            sys.exit(2)
    elif args.url:
        print(f">>> Gerando configuração automaticamente a partir de {args.url} ...")
        try:
            cfg = build_config_from_url(
                args.url, primary_token=args.token, secondary_token=args.secondary_token,
                username=args.username, password=args.password,
                verify_ssl=not args.no_verify_ssl,
            )
        except Exception as exc:
            print(f"✗ Erro ao descobrir endpoints a partir de '{args.url}': {exc!r}")
            sys.exit(2)
        try:
            save_config(cfg, args.save_config)
            print(f"✓ Configuração gerada e salva em '{args.save_config}' "
                  f"({len(cfg.endpoints)} endpoint(s) descoberto(s)). Edite esse arquivo e use "
                  f"--config na próxima vez se quiser refinar manualmente.")
        except Exception as exc:
            print(f"⚠ Não foi possível salvar o config gerado em '{args.save_config}': {exc!r}")
    else:
        print("✗ Especifique --url (modo automático) ou --config (arquivo existente), "
              "ou use o menu interativo.")
        sys.exit(2)

    if not confirm_authorization(assume_yes=args.yes):
        print("Operação cancelada: autorização não confirmada.")
        sys.exit(1)

    keys = list(TEST_REGISTRY.keys()) if args.all else (args.test or [])
    if not keys:
        print("✗ Especifique --all ou --test API1 API2 ...")
        sys.exit(2)

    findings = run_tests(cfg, keys)
    print_summary(findings)

    if args.output:
        if args.output.endswith(".json"):
            export_json(findings, args.output)
        else:
            export_html(findings, args.output, cfg.base_url)
        print(f"\n✓ Relatório salvo em {args.output}")


if __name__ == "__main__":
    main()

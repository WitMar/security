import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from fastapi import Body, Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response, status as http_status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

JWT_SECRET = os.getenv("SECURITY_LAB_JWT_SECRET", "dev-secret-change-me")
JWT_ISSUER = os.getenv("SECURITY_LAB_JWT_ISSUER", "https://identity.example.local")
JWT_AUDIENCE = os.getenv("SECURITY_LAB_JWT_AUDIENCE", "security-lab-api")
PASSWORD_PEPPER = os.getenv("SECURITY_LAB_PASSWORD_PEPPER", "dev-pepper-change-me")
DB_PATH = os.getenv("SECURITY_LAB_DB_PATH", ":memory:")
HASH_ITERATIONS = 120_000
CSRF_DEMO_SESSION_ID = "demo-session-alice"

EXERCISES: dict[str, dict[str, Any]] = {
    "sql_injection_basic": {
        "title": "SQL Injection — odczyt wielu użytkowników",
        "points": 10,
        "difficulty": "easy",
        "category": "SQL Injection",
        "info_value": 2,
        "goal": "Wyświetl więcej użytkowników niż powinien zwrócić pojedynczy identyfikator.",
        "hint": "Porównaj id=1 z warunkiem logicznym, który jest zawsze prawdziwy.",
        "evidence_type": "response_contains_multiple_users",
    },
    "sql_injection_schema": {
        "title": "SQL Injection — odczyt schematu SQLite",
        "points": 20,
        "difficulty": "medium",
        "category": "SQL Injection",
        "info_value": 4,
        "goal": "Odczytaj nazwy tabel i definicje CREATE TABLE z metadanych SQLite.",
        "hint": "SQLite przechowuje metadane w tabeli sqlite_master.",
        "evidence_type": "response_contains_schema",
    },
    "sql_injection_password_hashes": {
        "title": "SQL Injection — odczyt haseł i hashy",
        "points": 30,
        "difficulty": "hard",
        "category": "SQL Injection",
        "info_value": 5,
        "goal": "Wydobądź jawne hasło oraz hash hasła i porównaj sól dla dwóch użytkowników.",
        "hint": "Dopasuj kolumny UNION SELECT do pól id, username i role.",
        "evidence_type": "response_contains_password_hash",
    },
    "sql_injection_secure": {
        "title": "SQL Injection — porównanie z endpointem secure",
        "points": 5,
        "difficulty": "easy",
        "category": "SQL Injection",
        "info_value": 1,
        "goal": "Sprawdź, że endpoint secure traktuje parametr jako wartość, a nie kod SQL.",
        "hint": "Spróbuj użyć niepoprawnego typu parametru.",
        "evidence_type": "secure_endpoint_checked",
    },
    "reflected_xss": {
        "title": "Reflected XSS — wersja podatna",
        "points": 10,
        "difficulty": "easy",
        "category": "XSS",
        "info_value": 2,
        "goal": "Zaobserwuj odbicie HTML z parametru q w odpowiedzi.",
        "hint": "Przekaż prosty znacznik HTML w parametrze q.",
        "evidence_type": "raw_html_reflected",
    },
    "reflected_xss_secure": {
        "title": "Reflected XSS — wersja secure",
        "points": 5,
        "difficulty": "easy",
        "category": "XSS",
        "info_value": 1,
        "goal": "Porównaj kodowanie HTML w bezpieczniejszej wersji.",
        "hint": "Ten sam payload powinien zostać pokazany jako tekst.",
        "evidence_type": "escaped_html_observed",
    },
    "stored_xss": {
        "title": "Stored XSS — komentarze",
        "points": 15,
        "difficulty": "medium",
        "category": "XSS",
        "info_value": 3,
        "goal": "Zapisz treść HTML w komentarzu i odczytaj ją z listy komentarzy.",
        "hint": "Najpierw POST na /comments/vulnerable, potem GET tej samej ścieżki.",
        "evidence_type": "stored_html_rendered",
    },
    "stored_xss_secure": {
        "title": "Stored XSS — kodowanie komentarzy",
        "points": 5,
        "difficulty": "easy",
        "category": "XSS",
        "info_value": 1,
        "goal": "Sprawdź, że zapisany komentarz jest kodowany przed wyświetleniem.",
        "hint": "Porównaj /comments/vulnerable i /comments/secure.",
        "evidence_type": "stored_html_escaped",
    },
    "dom_xss": {
        "title": "DOM-based XSS — innerHTML",
        "points": 10,
        "difficulty": "medium",
        "category": "XSS",
        "info_value": 2,
        "goal": "Zaobserwuj różnicę między danymi w URL fragment a backendowym query stringiem.",
        "hint": "Dane po znaku # przetwarza JavaScript w przeglądarce.",
        "evidence_type": "inner_html_sink_observed",
    },
    "dom_xss_secure": {
        "title": "DOM-based XSS — textContent",
        "points": 5,
        "difficulty": "easy",
        "category": "XSS",
        "info_value": 1,
        "goal": "Sprawdź bezpieczniejszy sink DOM textContent.",
        "hint": "Ten sam fragment URL powinien być tekstem, nie HTML.",
        "evidence_type": "text_content_sink_observed",
    },
    "csp_headers": {
        "title": "Content Security Policy — analiza nagłówków",
        "points": 10,
        "difficulty": "medium",
        "category": "Security Headers",
        "info_value": 2,
        "goal": "Sprawdź nagłówki bezpieczeństwa i porównaj standardową CSP z wyjątkiem dla /dom/*.",
        "hint": "Użyj /security-headers oraz narzędzi developerskich w przeglądarce.",
        "evidence_type": "security_headers_observed",
    },
    "clickjacking_vulnerable": {
        "title": "Clickjacking — skuteczne osadzenie podatnego endpointu",
        "points": 10,
        "difficulty": "medium",
        "category": "Security Headers",
        "info_value": 2,
        "goal": "Zaobserwuj, że endpoint bez X-Frame-Options może zostać osadzony w iframe.",
        "hint": "Otwórz /clickjacking/demo i porównaj nagłówki z /admin.",
        "evidence_type": "vulnerable_endpoint_framed",
    },
    "csrf_session": {
        "title": "CSRF — pobranie sesji i tokenu",
        "points": 5,
        "difficulty": "easy",
        "category": "CSRF",
        "info_value": 1,
        "goal": "Pobierz demonstracyjne cookie sesyjne i token CSRF.",
        "hint": "Użyj /csrf/dev i zapisz cookie.",
        "evidence_type": "csrf_token_received",
    },
    "csrf_vulnerable": {
        "title": "CSRF — podatny transfer",
        "points": 15,
        "difficulty": "medium",
        "category": "CSRF",
        "info_value": 3,
        "goal": "Wykonaj transfer, który ufa samemu cookie sesyjnemu.",
        "hint": "Endpoint vulnerable nie wymaga nagłówka X-CSRF-Token.",
        "evidence_type": "state_change_without_csrf_token",
    },
    "csrf_secure": {
        "title": "CSRF — transfer z tokenem",
        "points": 10,
        "difficulty": "medium",
        "category": "CSRF",
        "info_value": 2,
        "goal": "Wykonaj transfer zabezpieczony poprawnym tokenem CSRF.",
        "hint": "Skopiuj csrf_token z /csrf/dev do nagłówka X-CSRF-Token.",
        "evidence_type": "csrf_token_validated",
    },
    "session_fixation_vulnerable": {
        "title": "Session Fixation — podatny login zachowuje session_id",
        "points": 10,
        "difficulty": "medium",
        "category": "Session Management",
        "info_value": 2,
        "goal": "Zaobserwuj, że narzucony identyfikator sesji pozostaje taki sam po zalogowaniu.",
        "hint": "Najpierw przygotuj znaną sesję, potem wykonaj podatny login.",
        "evidence_type": "session_id_not_regenerated",
    },
    "session_fixation_secure": {
        "title": "Session Fixation — bezpieczny login regeneruje session_id",
        "points": 10,
        "difficulty": "medium",
        "category": "Session Management",
        "info_value": 2,
        "goal": "Zaobserwuj, że po zalogowaniu aplikacja wydaje nowy identyfikator sesji.",
        "hint": "Porównaj session_id przed i po logowaniu w wariancie secure.",
        "evidence_type": "session_id_regenerated",
    },
    "session_hijacking_vulnerable": {
        "title": "Session Hijacking — użycie przejętej sesji",
        "points": 15,
        "difficulty": "medium",
        "category": "Session Management",
        "info_value": 3,
        "goal": "Użyj znanego identyfikatora sesji jako nagłówka i odczytaj profil użytkownika.",
        "hint": "Najpierw utwórz sesję demonstracyjną, potem wyślij jej identyfikator w X-Hijacked-Session.",
        "evidence_type": "stolen_session_reused",
    },
    "session_hijacking_secure": {
        "title": "Session Hijacking — rotacja i unieważnienie sesji",
        "points": 10,
        "difficulty": "medium",
        "category": "Session Management",
        "info_value": 2,
        "goal": "Zobacz, że po rotacji stary identyfikator sesji nie daje już dostępu.",
        "hint": "Porównaj stary session_id z nowym po /session-hijacking/rotate/secure.",
        "evidence_type": "stolen_session_invalidated",
    },
    "secure_login_jwt": {
        "title": "Bezpieczne logowanie i JWT",
        "points": 10,
        "difficulty": "easy",
        "category": "JWT/Auth",
        "info_value": 2,
        "goal": "Uzyskaj token JWT dla użytkownika i przeanalizuj jego użycie.",
        "hint": "Użyj /login/secure lub /token/dev.",
        "evidence_type": "jwt_issued",
    },
    "jwt_profile": {
        "title": "JWT — odczyt profilu",
        "points": 5,
        "difficulty": "easy",
        "category": "JWT/Auth",
        "info_value": 1,
        "goal": "Użyj tokenu Bearer do odczytu /profile.",
        "hint": "Nagłówek ma format Authorization: Bearer TOKEN.",
        "evidence_type": "profile_read_with_token",
    },
    "admin_access": {
        "title": "Broken Access Control — poprawny admin",
        "points": 15,
        "difficulty": "medium",
        "category": "Access Control",
        "info_value": 3,
        "goal": "Użyj tokenu admina i odczytaj panel administracyjny.",
        "hint": "Token użytkownika admin ma rolę admin.",
        "evidence_type": "admin_panel_accessed",
    },
    "admin_rejected": {
        "title": "Broken Access Control — blokada zwykłego użytkownika",
        "points": 10,
        "difficulty": "medium",
        "category": "Access Control",
        "info_value": 2,
        "goal": "Potwierdź, że zwykły użytkownik nie ma dostępu do /admin.",
        "hint": "Użyj tokenu alice i porównaj status HTTP.",
        "evidence_type": "forbidden_status_observed",
    },
}

EXERCISES.update(
    {
        "idor_vulnerable": {
            "title": "IDOR — odczyt cudzego zasobu",
            "points": 10,
            "difficulty": "medium",
            "category": "Access Control",
            "info_value": 3,
            "goal": "Zmień identyfikator faktury i odczytaj cudzy zasób.",
            "hint": "Porównaj invoice_id należący do alice i bob.",
            "evidence_type": "foreign_object_read",
        },
        "idor_secure": {
            "title": "IDOR — kontrola właściciela zasobu",
            "points": 5,
            "difficulty": "medium",
            "category": "Access Control",
            "info_value": 1,
            "goal": "Sprawdź, że secure endpoint odrzuca dostęp do cudzego zasobu.",
            "hint": "Endpoint secure sprawdza właściciela faktury.",
            "evidence_type": "owner_check_enforced",
        },
        "broken_access_control_vulnerable": {
            "title": "Broken Access Control — zmiana roli bez uprawnień",
            "points": 10,
            "difficulty": "medium",
            "category": "Access Control",
            "info_value": 3,
            "goal": "Zaobserwuj zmianę roli bez sprawdzenia uprawnień administratora.",
            "hint": "Wersja vulnerable ufa parametrowi roli.",
            "evidence_type": "role_changed_without_admin",
        },
        "broken_access_control_secure": {
            "title": "Broken Access Control — wymaganie roli admin",
            "points": 5,
            "difficulty": "medium",
            "category": "Access Control",
            "info_value": 1,
            "goal": "Sprawdź, że operacja administracyjna wymaga roli admin.",
            "hint": "Porównaj nagłówek X-Demo-Role: user i admin.",
            "evidence_type": "admin_role_required",
        },
        "command_injection_vulnerable": {
            "title": "Command Injection — doklejone polecenie",
            "points": 10,
            "difficulty": "medium",
            "category": "Injection",
            "info_value": 3,
            "goal": "Zaobserwuj, że dane wejściowe stają się fragmentem polecenia systemowego.",
            "hint": "Dodaj separator ; albo && do nazwy pliku.",
            "evidence_type": "command_split_observed",
        },
        "ldap_injection_vulnerable": {
            "title": "LDAP Injection — manipulacja filtrem",
            "points": 10,
            "difficulty": "medium",
            "category": "Injection",
            "info_value": 3,
            "goal": "Zaobserwuj, że znaki specjalne zmieniają filtr LDAP.",
            "hint": "Użyj znaków * ( ) | w nazwie użytkownika.",
            "evidence_type": "ldap_filter_manipulated",
        },
        "xpath_injection_vulnerable": {
            "title": "XPath Injection — manipulacja wyrażeniem",
            "points": 10,
            "difficulty": "medium",
            "category": "Injection",
            "info_value": 3,
            "goal": "Zaobserwuj obejście warunku XPath przez wyrażenie zawsze prawdziwe.",
            "hint": "Użyj wartości zawierającej ' or '1'='1.",
            "evidence_type": "xpath_expression_manipulated",
        },
        "cors_misconfiguration": {
            "title": "CORS — błędna konfiguracja origin i credentials",
            "points": 10,
            "difficulty": "medium",
            "category": "Security Headers",
            "info_value": 2,
            "goal": "Sprawdź, że podatny endpoint odbija niezaufany Origin z credentials.",
            "hint": "Wyślij nagłówek Origin: http://evil.example.",
            "evidence_type": "cors_origin_reflected",
        },
        "ssrf_vulnerable": {
            "title": "SSRF — dostęp do symulowanych metadanych",
            "points": 15,
            "difficulty": "hard",
            "category": "SSRF",
            "info_value": 4,
            "goal": "Zobacz, że backend pobiera zasób wskazany przez użytkownika.",
            "hint": "Użyj adresu 169.254.169.254 w parametrze url.",
            "evidence_type": "metadata_endpoint_reached",
        },
        "xxe_vulnerable": {
            "title": "XXE — zewnętrzna encja XML",
            "points": 15,
            "difficulty": "hard",
            "category": "XML",
            "info_value": 4,
            "goal": "Zaobserwuj symulowany odczyt sekretu przez external entity.",
            "hint": "Wyślij XML z DOCTYPE i ENTITY.",
            "evidence_type": "xxe_entity_expanded",
        },
        "deserialization_vulnerable": {
            "title": "Niebezpieczna deserializacja — zaufanie do obiektu",
            "points": 10,
            "difficulty": "medium",
            "category": "Deserialization",
            "info_value": 3,
            "goal": "Przekaż zakodowany obiekt z rolą admin i zobacz, że aplikacja mu ufa.",
            "hint": "Payload to base64 z JSON-em.",
            "evidence_type": "trusted_deserialized_role",
        },
        "path_traversal_vulnerable": {
            "title": "Path Traversal — odczyt spoza katalogu",
            "points": 10,
            "difficulty": "medium",
            "category": "File Access",
            "info_value": 3,
            "goal": "Użyj ../, aby odczytać symulowany plik sekretu.",
            "hint": "Spróbuj ../secrets/app.txt.",
            "evidence_type": "path_traversal_secret_read",
        },
        "lfi_rfi_vulnerable": {
            "title": "LFI/RFI — dołączenie pliku lub URL",
            "points": 10,
            "difficulty": "medium",
            "category": "File Access",
            "info_value": 3,
            "goal": "Zaobserwuj dołączanie lokalnego pliku albo zdalnego szablonu z parametru.",
            "hint": "Porównaj template=../../secrets/app.txt i template=https://evil.example/template.",
            "evidence_type": "unsafe_template_included",
        },
    }
)

app = FastAPI(title="Security Lab", version="2.0.0")


class LoginRequest(BaseModel):
    username: str
    password: str


class CommentRequest(BaseModel):
    author: str
    content: str


class TransferRequest(BaseModel):
    to_account: str
    amount: float


class StudentRequest(BaseModel):
    student_id: str = Field(min_length=2, max_length=80)
    name: str = Field(min_length=1, max_length=120)
    group_name: str | None = Field(default=None, max_length=80)


class UserRecord(BaseModel):
    id: int
    username: str
    role: str


class OrderRecord(BaseModel):
    id: int
    user_id: int
    product: str
    amount: float
    status: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    password_with_pepper = f"{password}{PASSWORD_PEPPER}".encode("utf-8")
    digest = hashlib.pbkdf2_hmac("sha256", password_with_pepper, salt, HASH_ITERATIONS)
    return f"pbkdf2_sha256${HASH_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        password_with_pepper = f"{password}{PASSWORD_PEPPER}".encode("utf-8")
        actual = hashlib.pbkdf2_hmac("sha256", password_with_pepper, salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def jwt_encode_hs256(payload: dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_part = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_part}.{payload_part}.{b64url_encode(signature)}"


def jwt_decode_hs256(token: str, secret: str, issuer: str, audience: str) -> dict[str, Any]:
    try:
        header_part, payload_part, signature_part = token.split(".")
        signing_input = f"{header_part}.{payload_part}".encode("ascii")
        expected_signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        provided_signature = b64url_decode(signature_part)
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise ValueError("Niepoprawny podpis tokenu")

        header = json.loads(b64url_decode(header_part))
        payload = json.loads(b64url_decode(payload_part))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Niepoprawny format tokenu") from exc

    if header.get("alg") != "HS256":
        raise ValueError("Nieobsługiwany algorytm tokenu")
    if payload.get("iss") != issuer:
        raise ValueError("Niepoprawny issuer")
    if payload.get("aud") != audience:
        raise ValueError("Niepoprawny audience")
    if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
        raise ValueError("Token wygasł")
    if "sub" not in payload:
        raise ValueError("Brak identyfikatora użytkownika")
    return payload


def create_csrf_token(session_id: str) -> str:
    return hmac.new(JWT_SECRET.encode("utf-8"), session_id.encode("utf-8"), hashlib.sha256).hexdigest()


def create_connection() -> sqlite3.Connection:
    if DB_PATH != ":memory:":
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    initialize_schema(connection)
    seed_demo_data(connection)
    return connection


def initialize_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_plain TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            product TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            author TEXT NOT NULL,
            content TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS students (
            student_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            group_name TEXT,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS exercise_progress (
            student_id TEXT NOT NULL,
            exercise_id TEXT NOT NULL,
            points INTEGER NOT NULL,
            evidence TEXT,
            completed_at TEXT NOT NULL,
            PRIMARY KEY(student_id, exercise_id),
            FOREIGN KEY(student_id) REFERENCES students(student_id)
        );
        """
    )
    connection.commit()


def table_is_empty(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(f"SELECT COUNT(*) AS count FROM {table_name}").fetchone()
    return int(row["count"]) == 0


def seed_demo_data(connection: sqlite3.Connection) -> None:
    if table_is_empty(connection, "users"):
        seed_users = [
            (1, "admin", "AdminPass2026!", "admin"),
            (2, "alice", "AlicePass2026!", "user"),
            (3, "bob", "BobPass2026!", "user"),
            (4, "charlie", "AlicePass2026!", "user"),
        ]
        for user_id, username, plain_password, role in seed_users:
            connection.execute(
                "INSERT INTO users(id, username, password_plain, password_hash, role) VALUES (?, ?, ?, ?, ?)",
                (user_id, username, plain_password, hash_password(plain_password), role),
            )

    if table_is_empty(connection, "orders"):
        seed_orders = [
            (1, 1, "Security audit", 1200.0, "paid"),
            (2, 2, "Laptop", 4500.0, "new"),
            (3, 2, "Keyboard", 350.0, "paid"),
            (4, 3, "Monitor", 900.0, "cancelled"),
        ]
        for order_id, user_id, product, amount, order_status in seed_orders:
            connection.execute(
                "INSERT INTO orders(id, user_id, product, amount, status) VALUES (?, ?, ?, ?, ?)",
                (order_id, user_id, product, amount, order_status),
            )

    if table_is_empty(connection, "comments"):
        seed_comments = [
            (1, "alice", "Pierwszy komentarz w systemie"),
            (2, "bob", "Komentarz zapisany w bazie"),
        ]
        for comment_id, author, content in seed_comments:
            connection.execute(
                "INSERT INTO comments(id, author, content) VALUES (?, ?, ?)",
                (comment_id, author, content),
            )
    connection.commit()


db = create_connection()
FIXATION_SESSIONS: dict[str, dict[str, Any]] = {}
HIJACKING_SESSIONS: dict[str, dict[str, Any]] = {}


def row_to_user(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def extract_student_id(request: Request, explicit_student_id: str | None = None) -> str | None:
    return explicit_student_id or request.query_params.get("student_id") or request.headers.get("X-Student-Id")


def ensure_student(student_id: str, name: str | None = None, group_name: str | None = None) -> None:
    now = utc_now()
    existing = db.execute("SELECT student_id FROM students WHERE student_id = ?", (student_id,)).fetchone()
    if existing is None:
        db.execute(
            "INSERT INTO students(student_id, name, group_name, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)",
            (student_id, name or student_id, group_name, now, now),
        )
    else:
        db.execute(
            "UPDATE students SET last_seen_at = ?, name = COALESCE(?, name), group_name = COALESCE(?, group_name) WHERE student_id = ?",
            (now, name, group_name, student_id),
        )
    db.commit()


def record_progress(request: Request, exercise_id: str, evidence: str | None = None) -> None:
    student_id = extract_student_id(request)
    if not student_id or exercise_id not in EXERCISES:
        return
    ensure_student(student_id)
    db.execute(
        """
        INSERT INTO exercise_progress(student_id, exercise_id, points, evidence, completed_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(student_id, exercise_id)
        DO UPDATE SET points = excluded.points, evidence = excluded.evidence, completed_at = excluded.completed_at
        """,
        (student_id, exercise_id, int(EXERCISES[exercise_id]["points"]), evidence, utc_now()),
    )
    db.commit()


def authenticate_user(username: str, password: str) -> sqlite3.Row | None:
    row = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None or not verify_password(password, row["password_hash"]):
        return None
    return row


def set_fixation_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        "fixation_session",
        session_id,
        httponly=True,
        samesite="lax",
    )


def set_hijacking_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        "hijack_session",
        session_id,
        httponly=True,
        samesite="lax",
    )


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    if not request.url.path.startswith("/clickjacking/vulnerable"):
        response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/dom/"):
        response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'; object-src 'none'"
    elif request.url.path.startswith("/clickjacking/"):
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'"
    else:
        response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'"
    return response


@app.get("/")
def root():
    return {
        "message": "Security Lab działa lokalnie",
        "docs": "/docs",
        "ranking": "/ranking",
        "scoreboard": "/scoreboard",
        "exercises": "/exercises",
        "challenges": "/challenges",
        "security_headers": "/security-headers",
        "clickjacking_demo": "/clickjacking/demo",
        "session_fixation_demo": "/session-fixation/dev",
        "session_hijacking_demo": "/session-hijacking/dev",
        "warning": "Endpointy /vulnerable są celowo podatne i służą tylko do nauki.",
    }


@app.get("/health")
def health():
    return {"status": "ok", "db_path": DB_PATH}


@app.get("/security-headers")
def security_headers(request: Request):
    record_progress(request, "csp_headers", "Sprawdzono nagłówki bezpieczeństwa")
    return {
        "headers_to_check": [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
        ],
        "default_csp": "default-src 'self'; object-src 'none'",
        "dom_demo_csp": "default-src 'self' 'unsafe-inline'; object-src 'none'",
        "clickjacking_demo": "Endpoint /clickjacking/vulnerable celowo nie ma X-Frame-Options, aby pokazać skuteczny clickjacking w laboratorium.",
        "note": "Endpointy /dom/* i /clickjacking/* mają luźniejsze nagłówki tylko w celach demonstracyjnych.",
    }


@app.get("/session-fixation/dev")
def session_fixation_prepare(response: Response, session_id: str = "known-session-before-login"):
    FIXATION_SESSIONS[session_id] = {
        "authenticated": False,
        "username": None,
        "created_for_demo": True,
    }
    set_fixation_cookie(response, session_id)
    return {
        "message": "Ustawiono demonstracyjne cookie sesyjne przed logowaniem.",
        "cookie_name": "fixation_session",
        "session_id": session_id,
        "authenticated": False,
    }


@app.post("/session-fixation/login/vulnerable")
def session_fixation_login_vulnerable(
    request: Request,
    response: Response,
    login: LoginRequest,
    fixation_session: str | None = Cookie(default=None),
):
    user = authenticate_user(login.username, login.password)
    if user is None:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Niepoprawne dane logowania")

    before_session_id = fixation_session or "known-session-before-login"
    after_session_id = before_session_id
    FIXATION_SESSIONS[after_session_id] = {
        "authenticated": True,
        "username": user["username"],
        "role": user["role"],
        "vulnerable": True,
    }
    set_fixation_cookie(response, after_session_id)
    record_progress(request, "session_fixation_vulnerable", "Login zachował identyfikator sesji")
    return {
        "mode": "vulnerable",
        "authenticated": True,
        "username": user["username"],
        "before_session_id": before_session_id,
        "after_session_id": after_session_id,
        "session_regenerated": False,
        "risk": "Identyfikator sesji ustawiony przed logowaniem pozostał aktywny po logowaniu.",
    }


@app.post("/session-fixation/login/secure")
def session_fixation_login_secure(
    request: Request,
    response: Response,
    login: LoginRequest,
    fixation_session: str | None = Cookie(default=None),
):
    user = authenticate_user(login.username, login.password)
    if user is None:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Niepoprawne dane logowania")

    before_session_id = fixation_session or "no-session-before-login"
    after_session_id = f"session-{secrets.token_urlsafe(18)}"
    if fixation_session:
        FIXATION_SESSIONS.pop(fixation_session, None)
    FIXATION_SESSIONS[after_session_id] = {
        "authenticated": True,
        "username": user["username"],
        "role": user["role"],
        "vulnerable": False,
    }
    set_fixation_cookie(response, after_session_id)
    record_progress(request, "session_fixation_secure", "Login wygenerował nowy identyfikator sesji")
    return {
        "mode": "secure",
        "authenticated": True,
        "username": user["username"],
        "before_session_id": before_session_id,
        "after_session_id": after_session_id,
        "session_regenerated": True,
        "protection": "Po logowaniu aplikacja unieważnia poprzedni identyfikator i wydaje nowy session_id.",
    }


@app.get("/session-hijacking/dev")
def session_hijacking_create_demo_session(request: Request, response: Response, username: str = "alice"):
    row = db.execute("SELECT username, role FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Nieznany użytkownik")

    session_id = f"hijack-{secrets.token_urlsafe(18)}"
    HIJACKING_SESSIONS[session_id] = {
        "username": row["username"],
        "role": row["role"],
        "active": True,
        "created_at": utc_now(),
    }
    set_hijacking_cookie(response, session_id)
    return {
        "message": "Utworzono demonstracyjną aktywną sesję użytkownika.",
        "warning": "W prawdziwej aplikacji session_id nie powinien być wypisywany w odpowiedzi ani logach.",
        "cookie_name": "hijack_session",
        "session_id": session_id,
        "username": row["username"],
        "role": row["role"],
    }


@app.get("/session-hijacking/profile/vulnerable")
def session_hijacking_profile_vulnerable(
    request: Request,
    hijack_session: str | None = Cookie(default=None),
    x_hijacked_session: str | None = Header(default=None, alias="X-Hijacked-Session"),
):
    session_id = x_hijacked_session or hijack_session
    if not session_id or session_id not in HIJACKING_SESSIONS:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Brak aktywnej sesji")

    session = HIJACKING_SESSIONS[session_id]
    record_progress(request, "session_hijacking_vulnerable", "Profil odczytany przy użyciu przejętego session_id")
    return {
        "mode": "vulnerable",
        "access_granted": True,
        "access_source": "X-Hijacked-Session" if x_hijacked_session else "cookie",
        "session_id": session_id,
        "username": session["username"],
        "role": session["role"],
        "risk": "Każdy, kto zna aktywny identyfikator sesji, może podszyć się pod użytkownika.",
    }


@app.post("/session-hijacking/rotate/secure")
def session_hijacking_rotate_secure(
    request: Request,
    response: Response,
    hijack_session: str | None = Cookie(default=None),
):
    if not hijack_session or hijack_session not in HIJACKING_SESSIONS:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Brak aktywnej sesji do rotacji")

    old_session = HIJACKING_SESSIONS.pop(hijack_session)
    new_session_id = f"hijack-{secrets.token_urlsafe(18)}"
    HIJACKING_SESSIONS[new_session_id] = {
        **old_session,
        "rotated_from": hijack_session,
        "rotated_at": utc_now(),
    }
    set_hijacking_cookie(response, new_session_id)
    record_progress(request, "session_hijacking_secure", "Stary session_id został unieważniony przez rotację")
    return {
        "mode": "secure",
        "old_session_id": hijack_session,
        "new_session_id": new_session_id,
        "old_session_invalidated": True,
        "protection": "Rotacja sesji ogranicza skutki przejęcia starego identyfikatora.",
    }


@app.get("/session-hijacking/profile/secure")
def session_hijacking_profile_secure(
    hijack_session: str | None = Cookie(default=None),
):
    if not hijack_session or hijack_session not in HIJACKING_SESSIONS:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Brak aktywnej sesji")

    session = HIJACKING_SESSIONS[hijack_session]
    return {
        "mode": "secure",
        "access_granted": True,
        "session_id": hijack_session,
        "username": session["username"],
        "role": session["role"],
        "note": "Ten endpoint korzysta z aktualnego cookie po rotacji, a nie ze starego identyfikatora przekazanego ręcznie.",
    }


@app.get("/clickjacking/demo", response_class=HTMLResponse)
def clickjacking_demo(student_id: str | None = None):
    student_query = f"?student_id={quote(student_id)}" if student_id else ""
    iframe_src = f"/clickjacking/vulnerable{student_query}"
    return HTMLResponse(
        f"""
        <!doctype html>
        <html lang="pl">
        <head>
          <meta charset="utf-8">
          <title>Clickjacking demo — strona atakująca</title>
          <style>
            body {{ font-family: Arial, sans-serif; margin: 32px; }}
            .attack-surface {{
              position: relative;
              width: 760px;
              height: 430px;
              border: 3px solid #b00020;
              background: linear-gradient(135deg, #fff8e1, #ffe0b2);
              overflow: hidden;
            }}
            .fake-content {{ padding: 32px; }}
            .bait-button {{
              position: absolute;
              top: 242px;
              left: 268px;
              padding: 18px 34px;
              font-size: 20px;
              border: 0;
              border-radius: 8px;
              color: white;
              background: #1976d2;
            }}
            iframe {{
              position: absolute;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              opacity: 0.08;
              z-index: 10;
              border: 0;
            }}
          </style>
        </head>
        <body>
          <h1>Demo clickjackingu — podatny endpoint</h1>
          <p>Ta strona udaje niewinną promocję, ale na wierzchu ma prawie przezroczysty iframe z endpointem podatnym.</p>
          <div class="attack-surface">
            <div class="fake-content">
              <h2>Odbierz bonus laboratoryjny</h2>
              <p>Kliknięcie w przycisk wizualnie wygląda niewinnie, ale faktycznie trafia w przycisk w osadzonym iframe.</p>
              <button class="bait-button">Odbierz bonus</button>
            </div>
            <iframe src="{iframe_src}" title="Podatny endpoint osadzony w iframe"></iframe>
          </div>
          <p><strong>Kontrola:</strong> spróbuj analogicznie osadzić <code>/admin</code>. Ten endpoint ma <code>X-Frame-Options: DENY</code>, więc przeglądarka powinna go zablokować.</p>
        </body>
        </html>
        """
    )


@app.get("/clickjacking/vulnerable", response_class=HTMLResponse)
def clickjacking_vulnerable(request: Request, student_id: str | None = None):
    record_progress(request, "clickjacking_vulnerable", "Podatny endpoint został osadzony w iframe")
    student_query = f"?student_id={quote(student_id)}" if student_id else ""
    return HTMLResponse(
        f"""
        <!doctype html>
        <html lang="pl">
        <head>
          <meta charset="utf-8">
          <title>Podatny endpoint clickjacking</title>
          <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: #fff; }}
            .panel {{ padding: 34px; }}
            .danger-button {{
              margin-top: 162px;
              margin-left: 232px;
              padding: 18px 34px;
              font-size: 20px;
              border: 0;
              border-radius: 8px;
              color: white;
              background: #c62828;
            }}
          </style>
        </head>
        <body>
          <div class="panel">
            <h2>Panel demonstracyjny</h2>
            <p>To jest celowo podatny endpoint. Brak nagłówka <code>X-Frame-Options</code> pozwala osadzić go w iframe.</p>
            <form method="post" action="/clickjacking/vulnerable/confirm{student_query}">
              <button class="danger-button" type="submit">Potwierdź operację</button>
            </form>
          </div>
        </body>
        </html>
        """
    )


@app.post("/clickjacking/vulnerable/confirm", response_class=HTMLResponse)
def clickjacking_vulnerable_confirm(request: Request):
    record_progress(request, "clickjacking_vulnerable", "Kliknięto ukrytą operację w iframe")
    return HTMLResponse(
        """
        <!doctype html>
        <html lang="pl">
        <head><meta charset="utf-8"><title>Operacja wykonana</title></head>
        <body>
          <h1>Operacja demonstracyjna została wykonana</h1>
          <p>W prawdziwej aplikacji podobny mechanizm mógłby wymusić kliknięcie w przelew, zmianę e-maila albo usunięcie konta.</p>
        </body>
        </html>
        """
    )


@app.post("/students")
def register_student(request: StudentRequest):
    ensure_student(request.student_id, request.name, request.group_name)
    return {"student_id": request.student_id, "name": request.name, "group_name": request.group_name}


@app.get("/exercises")
def list_exercises():
    return [
        {
            "exercise_id": exercise_id,
            "title": data["title"],
            "points": data["points"],
            "difficulty": data["difficulty"],
            "category": data["category"],
        }
        for exercise_id, data in EXERCISES.items()
    ]


@app.get("/challenges")
def list_challenges(difficulty: str | None = None, category: str | None = None):
    challenges = []
    for exercise_id, data in EXERCISES.items():
        if difficulty and data["difficulty"] != difficulty:
            continue
        if category and data["category"] != category:
            continue
        challenges.append(
            {
                "exercise_id": exercise_id,
                "title": data["title"],
                "points": data["points"],
                "difficulty": data["difficulty"],
                "category": data["category"],
                "info_value": data["info_value"],
                "goal": data["goal"],
                "hint": data["hint"],
            }
        )
    return challenges


@app.get("/progress")
def progress(student_id: str | None = None):
    params: tuple[Any, ...] = ()
    where = ""
    if student_id:
        where = "WHERE p.student_id = ?"
        params = (student_id,)
    rows = db.execute(
        f"""
        SELECT p.student_id, s.name, s.group_name, p.exercise_id, p.points, p.evidence, p.completed_at
        FROM exercise_progress p
        JOIN students s ON s.student_id = p.student_id
        {where}
        ORDER BY p.completed_at DESC
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]



@app.get("/ranking")
def ranking():
    rows = db.execute(
        """
        SELECT s.student_id, s.name, s.group_name,
               COUNT(p.exercise_id) AS completed_exercises,
               COALESCE(SUM(p.points), 0) AS points,
               MAX(p.completed_at) AS last_completed_at
        FROM students s
        LEFT JOIN exercise_progress p ON p.student_id = s.student_id
        GROUP BY s.student_id, s.name, s.group_name
        ORDER BY points DESC, completed_exercises DESC, s.name ASC
        """
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        completed = db.execute(
            "SELECT exercise_id FROM exercise_progress WHERE student_id = ?",
            (item["student_id"],),
        ).fetchall()
        item["information_score"] = sum(int(EXERCISES[row["exercise_id"]]["info_value"]) for row in completed)
        result.append(item)
    return result


@app.get("/scoreboard")
def scoreboard():
    rows = ranking()
    return sorted(rows, key=lambda item: (-item["information_score"], -item["points"], item["name"]))


DEMO_INVOICES = {
    1001: {"invoice_id": 1001, "owner": "alice", "amount": 1200.0, "description": "Laptop service"},
    1002: {"invoice_id": 1002, "owner": "bob", "amount": 900.0, "description": "Monitor order"},
}
DEMO_DIRECTORY = [
    {"uid": "alice", "cn": "Alice", "role": "user"},
    {"uid": "bob", "cn": "Bob", "role": "user"},
    {"uid": "admin", "cn": "Administrator", "role": "admin"},
]
DEMO_XML_USERS = [
    {"name": "alice", "password": "AlicePass2026!", "role": "user"},
    {"name": "admin", "password": "AdminPass2026!", "role": "admin"},
]
DEMO_FILES = {
    "public/readme.txt": "Publiczny plik demonstracyjny",
    "secrets/app.txt": "LAB_FILE_SECRET_2026",
}
ALLOWED_TEMPLATES = {
    "home": "<h1>Strona główna</h1>",
    "profile": "<h1>Profil użytkownika</h1>",
    "help": "<h1>Pomoc</h1>",
}


def reject_unsafe_filename(filename: str) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", filename):
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="Niedozwolona nazwa pliku")


def is_private_or_metadata_host(hostname: str | None) -> bool:
    if not hostname:
        return True
    return hostname in {"169.254.169.254", "localhost", "127.0.0.1"} or hostname.startswith("10.") or hostname.startswith("192.168.")


@app.get("/idor/invoices/vulnerable")
def idor_invoice_vulnerable(request: Request, invoice_id: int, username: str = "alice"):
    invoice = DEMO_INVOICES.get(invoice_id)
    if invoice is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Nie znaleziono faktury")
    record_progress(request, "idor_vulnerable", f"{username} read invoice {invoice_id}")
    return {"mode": "vulnerable", "requested_by": username, "invoice": invoice, "owner_checked": False}


@app.get("/idor/invoices/secure")
def idor_invoice_secure(request: Request, invoice_id: int, username: str = "alice"):
    invoice = DEMO_INVOICES.get(invoice_id)
    if invoice is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Nie znaleziono faktury")
    if invoice["owner"] != username:
        record_progress(request, "idor_secure", f"{username} blocked from invoice {invoice_id}")
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Faktura należy do innego użytkownika")
    record_progress(request, "idor_secure", f"{username} read own invoice {invoice_id}")
    return {"mode": "secure", "requested_by": username, "invoice": invoice, "owner_checked": True}


@app.post("/access-control/change-role/vulnerable")
def change_role_vulnerable(request: Request, username: str, role: str):
    record_progress(request, "broken_access_control_vulnerable", f"{username}:{role}")
    return {"mode": "vulnerable", "username": username, "new_role": role, "admin_checked": False}


@app.post("/access-control/change-role/secure")
def change_role_secure(request: Request, username: str, role: str, x_demo_role: str = Header(default="user", alias="X-Demo-Role")):
    if x_demo_role != "admin":
        record_progress(request, "broken_access_control_secure", "non-admin rejected")
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Wymagana rola admin")
    record_progress(request, "broken_access_control_secure", "admin accepted")
    return {"mode": "secure", "username": username, "new_role": role, "admin_checked": True}


@app.get("/command/vulnerable")
def command_injection_vulnerable(request: Request, filename: str):
    command = f"convert {filename} output.png"
    separators = [";", "&&", "|"]
    injected = any(separator in filename for separator in separators)
    simulated_commands = re.split(r"\s*(?:;|&&|\|)\s*", command) if injected else [command]
    record_progress(request, "command_injection_vulnerable", filename)
    return {"mode": "vulnerable", "command": command, "injected": injected, "simulated_commands": simulated_commands}


@app.get("/command/secure")
def command_injection_secure(filename: str):
    reject_unsafe_filename(filename)
    return {"mode": "secure", "arguments": ["convert", filename, "output.png"], "shell": False}


@app.get("/ldap/vulnerable")
def ldap_injection_vulnerable(request: Request, username: str):
    ldap_filter = f"(uid={username})"
    injected = any(char in username for char in ["*", "(", ")", "|"])
    results = DEMO_DIRECTORY if injected else [entry for entry in DEMO_DIRECTORY if entry["uid"] == username]
    record_progress(request, "ldap_injection_vulnerable", ldap_filter)
    return {"mode": "vulnerable", "filter": ldap_filter, "injected": injected, "results": results}


@app.get("/ldap/secure")
def ldap_injection_secure(username: str):
    escaped = username.translate(str.maketrans({"*": r"\2a", "(": r"\28", ")": r"\29", "\\": r"\5c", "\x00": r"\00"}))
    results = [entry for entry in DEMO_DIRECTORY if entry["uid"] == username]
    return {"mode": "secure", "filter": f"(uid={escaped})", "results": results}


@app.get("/xpath/vulnerable")
def xpath_injection_vulnerable(request: Request, username: str, password: str = ""):
    expression = f"//user[name='{username}' and password='{password}']"
    injected = "' or '1'='1" in username.lower() or "' or '1'='1" in password.lower()
    results = DEMO_XML_USERS if injected else [user for user in DEMO_XML_USERS if user["name"] == username and user["password"] == password]
    record_progress(request, "xpath_injection_vulnerable", expression)
    return {"mode": "vulnerable", "expression": expression, "injected": injected, "results": [{"name": user["name"], "role": user["role"]} for user in results]}


@app.get("/xpath/secure")
def xpath_injection_secure(username: str, password: str = ""):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,40}", username):
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="Niepoprawny username")
    results = [user for user in DEMO_XML_USERS if user["name"] == username and user["password"] == password]
    return {"mode": "secure", "parameterized": True, "results": [{"name": user["name"], "role": user["role"]} for user in results]}


@app.get("/cors/vulnerable")
def cors_vulnerable(request: Request, response: Response):
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    record_progress(request, "cors_misconfiguration", origin)
    return {"mode": "vulnerable", "origin_reflected": origin, "credentials": True}


@app.get("/cors/secure")
def cors_secure(request: Request, response: Response):
    origin = request.headers.get("Origin")
    if origin == "https://trusted.example.edu":
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return {"mode": "secure", "origin_allowed": origin == "https://trusted.example.edu"}


@app.get("/ssrf/vulnerable")
def ssrf_vulnerable(request: Request, url: str):
    parsed = urlparse(url)
    metadata_hit = parsed.hostname == "169.254.169.254"
    record_progress(request, "ssrf_vulnerable", url)
    return {
        "mode": "vulnerable",
        "requested_url": url,
        "backend_request_simulated": True,
        "metadata": {"iam_role": "demo-admin-role", "token": "DEMO_METADATA_TOKEN"} if metadata_hit else None,
    }


@app.get("/ssrf/secure")
def ssrf_secure(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {"https"} or is_private_or_metadata_host(parsed.hostname):
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="URL zablokowany przez allowlistę")
    return {"mode": "secure", "requested_url": url, "allowed": True}


@app.post("/xxe/vulnerable")
def xxe_vulnerable(request: Request, xml_payload: str = Body(..., media_type="application/xml")):
    expanded_secret = "LAB_XML_SECRET_2026" if "<!ENTITY" in xml_payload and "file://" in xml_payload else None
    record_progress(request, "xxe_vulnerable", "entity expanded" if expanded_secret else "xml parsed")
    return {"mode": "vulnerable", "external_entity_seen": "<!ENTITY" in xml_payload, "expanded_secret": expanded_secret}


@app.post("/xxe/secure")
def xxe_secure(xml_payload: str = Body(..., media_type="application/xml")):
    if "<!DOCTYPE" in xml_payload or "<!ENTITY" in xml_payload:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="DTD i external entities są zablokowane")
    return {"mode": "secure", "parsed": True}


@app.get("/deserialize/vulnerable")
def deserialize_vulnerable(request: Request, payload: str):
    decoded = base64.b64decode(payload).decode("utf-8")
    obj = json.loads(decoded)
    record_progress(request, "deserialization_vulnerable", decoded)
    return {"mode": "vulnerable", "trusted_object": obj, "is_admin": obj.get("role") == "admin"}


@app.get("/deserialize/secure")
def deserialize_secure(payload: str):
    decoded = base64.b64decode(payload).decode("utf-8")
    obj = json.loads(decoded)
    allowed = {"username"}
    return {"mode": "secure", "accepted": {key: value for key, value in obj.items() if key in allowed}, "ignored_fields": sorted(set(obj) - allowed)}


@app.get("/files/vulnerable")
def path_traversal_vulnerable(request: Request, path: str):
    normalized = path.replace("\\", "/")
    key = "secrets/app.txt" if ".." in normalized and "secrets/app.txt" in normalized else normalized.lstrip("/")
    content = DEMO_FILES.get(key)
    if content is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Plik nie istnieje")
    record_progress(request, "path_traversal_vulnerable", path)
    return {"mode": "vulnerable", "requested_path": path, "resolved_key": key, "content": content}


@app.get("/files/secure")
def path_traversal_secure(path: str):
    normalized = path.replace("\\", "/")
    if ".." in normalized or normalized.startswith("/"):
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="Path traversal zablokowany")
    content = DEMO_FILES.get(normalized)
    if content is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Plik nie istnieje")
    return {"mode": "secure", "requested_path": path, "content": content}


@app.get("/include/vulnerable")
def lfi_rfi_vulnerable(request: Request, template: str):
    if template.startswith("http://") or template.startswith("https://"):
        result = {"type": "RFI", "included": "REMOTE_TEMPLATE_SIMULATED", "source": template}
    elif ".." in template and "secrets/app.txt" in template:
        result = {"type": "LFI", "included": DEMO_FILES["secrets/app.txt"], "source": template}
    else:
        result = {"type": "local", "included": ALLOWED_TEMPLATES.get(template, "UNKNOWN_TEMPLATE"), "source": template}
    record_progress(request, "lfi_rfi_vulnerable", template)
    return {"mode": "vulnerable", **result}


@app.get("/include/secure")
def lfi_rfi_secure(template: str):
    if template not in ALLOWED_TEMPLATES:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="Szablon spoza allowlisty")
    return {"mode": "secure", "template": template, "included": ALLOWED_TEMPLATES[template]}


@app.get("/users/vulnerable")
def get_user_vulnerable(request: Request, id: str = Query(..., description="Celowo string, aby pokazać SQL Injection")):
    query = f"SELECT id, username, role FROM users WHERE id = {id}"
    rows = db.execute(query).fetchall()
    lowered_id = id.lower()
    if "password_hash" in lowered_id or "password_plain" in lowered_id:
        record_progress(request, "sql_injection_password_hashes", "Odczyt password_plain/password_hash")
    elif "sqlite_master" in lowered_id:
        record_progress(request, "sql_injection_schema", "Odczyt sqlite_master")
    else:
        record_progress(request, "sql_injection_basic", id)
    return {"query": query, "users": [dict(row) for row in rows]}


@app.get("/users/secure")
def get_user_secure(request: Request, user_id: int):
    rows = db.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchall()
    record_progress(request, "sql_injection_secure", str(user_id))
    return {"users": [dict(row) for row in rows]}


@app.get("/orders/vulnerable")
def get_orders_vulnerable(request: Request, user_id: str = Query(..., description="Celowo string, aby pokazać SQL Injection")):
    query = f"SELECT id, user_id, product, amount, status FROM orders WHERE user_id = {user_id}"
    rows = db.execute(query).fetchall()
    record_progress(request, "sql_injection_orders", user_id)
    return {"query": query, "orders": [dict(row) for row in rows]}


@app.get("/orders/secure", response_model=list[OrderRecord])
def get_orders_secure(user_id: int):
    rows = db.execute(
        "SELECT id, user_id, product, amount, status FROM orders WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    return [OrderRecord(**dict(row)) for row in rows]


@app.get("/search/vulnerable", response_class=HTMLResponse)
def search_vulnerable(request: Request, q: str = ""):
    record_progress(request, "reflected_xss", q)
    return HTMLResponse(f"<h1>Wyniki dla: {q}</h1><p>To jest celowo podatna wersja.</p>")


@app.get("/search/secure", response_class=HTMLResponse)
def search_secure(request: Request, q: str = ""):
    safe_q = html.escape(q)
    record_progress(request, "reflected_xss_secure", q)
    return HTMLResponse(f"<h1>Wyniki dla: {safe_q}</h1><p>Dane użytkownika zostały zakodowane.</p>")


@app.post("/comments/vulnerable")
def add_comment_vulnerable(request: Request, comment: CommentRequest):
    cursor = db.execute(
        "INSERT INTO comments(author, content) VALUES (?, ?)",
        (comment.author, comment.content),
    )
    db.commit()
    record_progress(request, "stored_xss", comment.content)
    return {"id": cursor.lastrowid, "stored": comment.content}


@app.get("/comments/vulnerable", response_class=HTMLResponse)
def list_comments_vulnerable(request: Request):
    rows = db.execute("SELECT author, content FROM comments ORDER BY id").fetchall()
    items = "".join(f"<li><strong>{row['author']}</strong>: {row['content']}</li>" for row in rows)
    record_progress(request, "stored_xss", "Odczyt podatnej listy komentarzy")
    return HTMLResponse(f"<h1>Komentarze</h1><ul>{items}</ul><p>To jest celowo podatna wersja.</p>")


@app.post("/comments/secure")
def add_comment_secure(request: Request, comment: CommentRequest):
    cursor = db.execute(
        "INSERT INTO comments(author, content) VALUES (?, ?)",
        (comment.author, comment.content),
    )
    db.commit()
    record_progress(request, "stored_xss_secure", comment.content)
    return {"id": cursor.lastrowid, "stored": comment.content}


@app.get("/comments/secure", response_class=HTMLResponse)
def list_comments_secure(request: Request):
    rows = db.execute("SELECT author, content FROM comments ORDER BY id").fetchall()
    items = "".join(
        f"<li><strong>{html.escape(row['author'])}</strong>: {html.escape(row['content'])}</li>" for row in rows
    )
    record_progress(request, "stored_xss_secure", "Odczyt bezpieczniejszej listy komentarzy")
    return HTMLResponse(f"<h1>Komentarze</h1><ul>{items}</ul><p>Dane komentarzy zostały zakodowane.</p>")


@app.get("/dom/vulnerable", response_class=HTMLResponse)
def dom_vulnerable(request: Request):
    record_progress(request, "dom_xss", "Strona używa innerHTML")
    return HTMLResponse(
        """
        <h1>DOM XSS — wersja podatna</h1>
        <p>Dodaj tekst po znaku # w adresie, np. /dom/vulnerable#<b>test</b></p>
        <div id="result"></div>
        <script>
          const value = decodeURIComponent(window.location.hash.substring(1));
          document.getElementById('result').innerHTML = value;
        </script>
        """
    )


@app.get("/dom/secure", response_class=HTMLResponse)
def dom_secure(request: Request):
    record_progress(request, "dom_xss_secure", "Strona używa textContent")
    return HTMLResponse(
        """
        <h1>DOM XSS — wersja bezpieczniejsza</h1>
        <p>Dodaj tekst po znaku # w adresie, np. /dom/secure#<b>test</b></p>
        <div id="result"></div>
        <script>
          const value = decodeURIComponent(window.location.hash.substring(1));
          document.getElementById('result').textContent = value;
        </script>
        """
    )


@app.get("/csrf/dev")
def create_demo_csrf_session(request: Request, response: Response):
    csrf_token = create_csrf_token(CSRF_DEMO_SESSION_ID)
    response.set_cookie(
        key="demo_session",
        value=CSRF_DEMO_SESSION_ID,
        httponly=True,
        samesite="lax",
    )
    record_progress(request, "csrf_session", "Pobrano sesję CSRF")
    return {
        "message": "Ustawiono demonstracyjne cookie sesyjne",
        "csrf_token": csrf_token,
        "usage": "Wyślij token w nagłówku X-CSRF-Token do /transfer/secure",
    }


@app.post("/transfer/vulnerable")
def transfer_vulnerable(request: Request, transfer: TransferRequest, demo_session: str | None = Cookie(default=None)):
    if demo_session != CSRF_DEMO_SESSION_ID:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Brak demonstracyjnej sesji")
    record_progress(request, "csrf_vulnerable", f"{transfer.to_account}:{transfer.amount}")
    return {
        "status": "accepted",
        "to_account": transfer.to_account,
        "amount": transfer.amount,
        "warning": "Transfer zaakceptowany bez tokenu CSRF — wersja podatna.",
    }


@app.post("/transfer/secure")
def transfer_secure(
    request: Request,
    transfer: TransferRequest,
    demo_session: str | None = Cookie(default=None),
    x_csrf_token: str | None = Header(default=None),
):
    if demo_session != CSRF_DEMO_SESSION_ID:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Brak demonstracyjnej sesji")
    expected_token = create_csrf_token(demo_session)
    if not x_csrf_token or not hmac.compare_digest(x_csrf_token, expected_token):
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Niepoprawny token CSRF")
    record_progress(request, "csrf_secure", f"{transfer.to_account}:{transfer.amount}")
    return {
        "status": "accepted",
        "to_account": transfer.to_account,
        "amount": transfer.amount,
        "csrf": "validated",
    }


@app.post("/login/vulnerable")
def login_vulnerable(request: Request, login: LoginRequest):
    query = f"SELECT id, username, role FROM users WHERE username = '{login.username}' AND password_plain = '{login.password}'"
    rows = db.execute(query).fetchall()
    if not rows:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Błędny login lub hasło")
    return {"query": query, "user": dict(rows[0])}


@app.post("/login/secure")
def login_secure(request: Request, login: LoginRequest):
    row = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (login.username,),
    ).fetchone()
    if row is None or not verify_password(login.password, row["password_hash"]):
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Błędny login lub hasło")
    token = create_token(username=row["username"], role=row["role"])
    record_progress(request, "secure_login_jwt", login.username)
    return {"access_token": token, "token_type": "Bearer"}


def create_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    return jwt_encode_hs256(payload, JWT_SECRET)


@app.get("/token/dev", response_model=TokenResponse)
def create_dev_token(request: Request, username: str = "alice"):
    row = db.execute("SELECT username, role FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Nie ma takiego użytkownika")
    if username == "admin":
        record_progress(request, "admin_access", "Pobrano token admina")
    else:
        record_progress(request, "secure_login_jwt", f"Token dev dla {username}")
    return TokenResponse(access_token=create_token(username=row["username"], role=row["role"]))


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Brak tokenu Bearer")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt_decode_hs256(token, JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE)
    except ValueError as exc:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Niepoprawny token") from exc

    row = db.execute("SELECT id, username, role FROM users WHERE username = ?", (payload["sub"],)).fetchone()
    if row is None:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Użytkownik nie istnieje")
    return row_to_user(row)


def require_admin(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Wymagana rola admin")
    return user


@app.get("/profile", response_model=UserRecord)
def profile(request: Request, user: dict[str, Any] = Depends(get_current_user)):
    record_progress(request, "jwt_profile", user["username"])
    return UserRecord(**user)


@app.get("/admin")
def admin_panel(request: Request, user: dict[str, Any] = Depends(get_current_user)):
    if user["role"] != "admin":
        record_progress(request, "admin_rejected", user["username"])
        raise HTTPException(status_code=http_status.HTTP_403_FORBIDDEN, detail="Wymagana rola admin")
    record_progress(request, "admin_access", user["username"])
    return {"message": "Witaj w panelu administracyjnym", "user": user}


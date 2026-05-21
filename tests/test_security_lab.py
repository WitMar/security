import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app  # noqa: E402

client = TestClient(app)


def test_vulnerable_sql_endpoint_shows_injection_effect():
    response = client.get("/users/vulnerable", params={"id": "1 OR 1=1"})

    assert response.status_code == 200
    body = response.json()
    assert "1 OR 1=1" in body["query"]
    assert len(body["users"]) == 4


def test_vulnerable_sql_endpoint_can_leak_plain_and_hashed_passwords():
    response = client.get(
        "/users/vulnerable",
        params={
            "id": "0 UNION SELECT id,password_plain,password_hash FROM users WHERE username IN ('alice','charlie')",
        },
    )

    assert response.status_code == 200
    leaked_users = response.json()["users"]
    assert len(leaked_users) == 2
    assert leaked_users[0]["username"] == "AlicePass2026!"
    assert leaked_users[1]["username"] == "AlicePass2026!"
    assert leaked_users[0]["role"].startswith("pbkdf2_sha256$")
    assert leaked_users[1]["role"].startswith("pbkdf2_sha256$")
    assert leaked_users[0]["role"] != leaked_users[1]["role"]


def test_secure_sql_endpoint_rejects_non_integer_input():
    response = client.get("/users/secure", params={"user_id": "1 OR 1=1"})

    assert response.status_code == 422


def test_secure_sql_endpoint_uses_parameterized_query():
    response = client.get("/users/secure", params={"user_id": 1})

    assert response.status_code == 200
    assert response.json()["users"] == [{"id": 1, "username": "admin", "role": "admin"}]


def test_orders_secure_endpoint_returns_user_orders():
    response = client.get("/orders/secure", params={"user_id": 2})

    assert response.status_code == 200
    assert response.json() == [
        {"id": 2, "user_id": 2, "product": "Laptop", "amount": 4500.0, "status": "new"},
        {"id": 3, "user_id": 2, "product": "Keyboard", "amount": 350.0, "status": "paid"},
    ]


def test_orders_vulnerable_endpoint_shows_injection_effect():
    response = client.get("/orders/vulnerable", params={"user_id": "2 OR 1=1"})

    assert response.status_code == 200
    body = response.json()
    assert "2 OR 1=1" in body["query"]
    assert len(body["orders"]) == 4


def test_orders_secure_endpoint_rejects_non_integer_input():
    response = client.get("/orders/secure", params={"user_id": "2 OR 1=1"})

    assert response.status_code == 422


def test_vulnerable_search_reflects_raw_html():
    response = client.get("/search/vulnerable", params={"q": "<b>test</b>"})

    assert response.status_code == 200
    assert "<b>test</b>" in response.text


def test_secure_search_escapes_html():
    response = client.get("/search/secure", params={"q": "<b>test</b>"})

    assert response.status_code == 200
    assert "<b>test</b>" not in response.text
    assert "&lt;b&gt;test&lt;/b&gt;" in response.text


def test_stored_xss_vulnerable_comments_render_raw_html():
    payload = "<img src=x onerror=alert('stored')>"

    post_response = client.post("/comments/vulnerable", json={"author": "student", "content": payload})
    response = client.get("/comments/vulnerable")

    assert post_response.status_code == 200
    assert response.status_code == 200
    assert payload in response.text


def test_stored_xss_secure_comments_escape_html():
    payload = "<img src=x onerror=alert('safe')>"

    post_response = client.post("/comments/secure", json={"author": "student", "content": payload})
    response = client.get("/comments/secure")

    assert post_response.status_code == 200
    assert response.status_code == 200
    assert payload not in response.text
    assert "&lt;img src=x onerror=alert(&#x27;safe&#x27;)&gt;" in response.text


def test_dom_xss_vulnerable_page_uses_inner_html():
    response = client.get("/dom/vulnerable")

    assert response.status_code == 200
    assert "innerHTML" in response.text
    assert "unsafe-inline" in response.headers["Content-Security-Policy"]


def test_dom_xss_secure_page_uses_text_content():
    response = client.get("/dom/secure")

    assert response.status_code == 200
    assert "textContent" in response.text


def test_csrf_vulnerable_transfer_accepts_request_without_csrf_token():
    csrf_client = TestClient(app)
    csrf_client.get("/csrf/dev")

    response = csrf_client.post(
        "/transfer/vulnerable",
        json={"to_account": "PL001234", "amount": 100.0},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert "bez tokenu CSRF" in response.json()["warning"]


def test_csrf_secure_transfer_rejects_missing_token():
    csrf_client = TestClient(app)
    csrf_client.get("/csrf/dev")

    response = csrf_client.post(
        "/transfer/secure",
        json={"to_account": "PL001234", "amount": 100.0},
    )

    assert response.status_code == 403


def test_csrf_secure_transfer_accepts_valid_token():
    csrf_client = TestClient(app)
    token = csrf_client.get("/csrf/dev").json()["csrf_token"]

    response = csrf_client.post(
        "/transfer/secure",
        headers={"X-CSRF-Token": token},
        json={"to_account": "PL001234", "amount": 100.0},
    )

    assert response.status_code == 200
    assert response.json()["csrf"] == "validated"


def test_session_fixation_vulnerable_login_keeps_pre_login_session_id():
    fixation_client = TestClient(app)
    prepared = fixation_client.get(
        "/session-fixation/dev",
        params={"session_id": "attacker-known-session"},
    )

    response = fixation_client.post(
        "/session-fixation/login/vulnerable",
        params={"student_id": "session-fixation-test"},
        json={"username": "alice", "password": "AlicePass2026!"},
    )

    assert prepared.status_code == 200
    assert prepared.json()["session_id"] == "attacker-known-session"
    assert response.status_code == 200
    body = response.json()
    assert body["before_session_id"] == "attacker-known-session"
    assert body["after_session_id"] == "attacker-known-session"
    assert body["session_regenerated"] is False


def test_session_fixation_secure_login_regenerates_session_id():
    fixation_client = TestClient(app)
    prepared = fixation_client.get(
        "/session-fixation/dev",
        params={"session_id": "attacker-known-session-secure"},
    )

    response = fixation_client.post(
        "/session-fixation/login/secure",
        params={"student_id": "session-fixation-test"},
        json={"username": "alice", "password": "AlicePass2026!"},
    )

    assert prepared.status_code == 200
    assert prepared.json()["session_id"] == "attacker-known-session-secure"
    assert response.status_code == 200
    body = response.json()
    assert body["before_session_id"] == "attacker-known-session-secure"
    assert body["after_session_id"] != "attacker-known-session-secure"
    assert body["session_regenerated"] is True


def test_session_hijacking_vulnerable_profile_accepts_stolen_session_header():
    victim_client = TestClient(app)
    created = victim_client.get("/session-hijacking/dev", params={"username": "alice"})
    stolen_session_id = created.json()["session_id"]

    attacker_response = client.get(
        "/session-hijacking/profile/vulnerable",
        params={"student_id": "session-hijacking-test"},
        headers={"X-Hijacked-Session": stolen_session_id},
    )

    assert created.status_code == 200
    assert stolen_session_id.startswith("hijack-")
    assert attacker_response.status_code == 200
    body = attacker_response.json()
    assert body["access_granted"] is True
    assert body["access_source"] == "X-Hijacked-Session"
    assert body["username"] == "alice"


def test_session_hijacking_secure_rotation_invalidates_old_session_id():
    victim_client = TestClient(app)
    created = victim_client.get("/session-hijacking/dev", params={"username": "alice"})
    old_session_id = created.json()["session_id"]

    rotate_response = victim_client.post(
        "/session-hijacking/rotate/secure",
        params={"student_id": "session-hijacking-test"},
    )
    attacker_response = client.get(
        "/session-hijacking/profile/vulnerable",
        headers={"X-Hijacked-Session": old_session_id},
    )
    secure_profile_response = victim_client.get("/session-hijacking/profile/secure")

    assert created.status_code == 200
    assert rotate_response.status_code == 200
    body = rotate_response.json()
    assert body["old_session_id"] == old_session_id
    assert body["new_session_id"] != old_session_id
    assert body["old_session_invalidated"] is True
    assert attacker_response.status_code == 401
    assert secure_profile_response.status_code == 200
    assert secure_profile_response.json()["session_id"] == body["new_session_id"]


def test_secure_login_returns_token_for_valid_user():
    response = client.post(
        "/login/secure",
        json={"username": "alice", "password": "AlicePass2026!"},
    )

    assert response.status_code == 200
    assert response.json()["token_type"] == "Bearer"
    assert response.json()["access_token"]


def test_profile_requires_bearer_token():
    response = client.get("/profile")

    assert response.status_code == 401


def test_profile_accepts_valid_token():
    token = client.get("/token/dev", params={"username": "alice"}).json()["access_token"]

    response = client.get("/profile", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["username"] == "alice"
    assert response.json()["role"] == "user"


def test_admin_rejects_normal_user():
    token = client.get("/token/dev", params={"username": "alice"}).json()["access_token"]

    response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_admin_accepts_admin_user():
    token = client.get("/token/dev", params={"username": "admin"}).json()["access_token"]

    response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "admin"


def test_invalid_token_is_rejected():
    response = client.get("/profile", headers={"Authorization": "Bearer invalid-token"})

    assert response.status_code == 401


def test_security_headers_are_added():
    response = client.get("/")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src" in response.headers["Content-Security-Policy"]


def test_clickjacking_vulnerable_endpoint_can_be_framed_for_demo():
    response = client.get("/clickjacking/vulnerable", params={"student_id": "clickjack-test"})

    assert response.status_code == 200
    assert "X-Frame-Options" not in response.headers
    assert "Potwierdź operację" in response.text


def test_clickjacking_demo_contains_iframe_to_vulnerable_endpoint():
    response = client.get("/clickjacking/demo", params={"student_id": "clickjack-test"})

    assert response.status_code == 200
    assert "iframe" in response.text
    assert "/clickjacking/vulnerable?student_id=clickjack-test" in response.text


def test_clickjacking_vulnerable_confirm_shows_demo_operation_completed():
    response = client.post("/clickjacking/vulnerable/confirm", params={"student_id": "clickjack-test"})

    assert response.status_code == 200
    assert "Operacja demonstracyjna została wykonana" in response.text


def test_admin_endpoint_still_blocks_framing_even_when_unauthorized():
    response = client.get("/admin")

    assert response.status_code == 401
    assert response.headers["X-Frame-Options"] == "DENY"


def test_idor_vulnerable_reads_foreign_invoice_and_secure_blocks_it():
    vulnerable = client.get("/idor/invoices/vulnerable", params={"invoice_id": 1002, "username": "alice"})
    secure = client.get("/idor/invoices/secure", params={"invoice_id": 1002, "username": "alice"})

    assert vulnerable.status_code == 200
    assert vulnerable.json()["invoice"]["owner"] == "bob"
    assert vulnerable.json()["owner_checked"] is False
    assert secure.status_code == 403


def test_broken_access_control_vulnerable_changes_role_and_secure_requires_admin():
    vulnerable = client.post("/access-control/change-role/vulnerable", params={"username": "alice", "role": "admin"})
    rejected = client.post("/access-control/change-role/secure", params={"username": "alice", "role": "admin"})
    accepted = client.post(
        "/access-control/change-role/secure",
        params={"username": "alice", "role": "admin"},
        headers={"X-Demo-Role": "admin"},
    )

    assert vulnerable.status_code == 200
    assert vulnerable.json()["admin_checked"] is False
    assert rejected.status_code == 403
    assert accepted.status_code == 200
    assert accepted.json()["admin_checked"] is True


def test_command_ldap_and_xpath_injection_examples_show_manipulation():
    command = client.get("/command/vulnerable", params={"filename": "image.png; whoami"})
    ldap = client.get("/ldap/vulnerable", params={"username": "*)(|(role=admin))"})
    xpath = client.get("/xpath/vulnerable", params={"username": "' or '1'='1", "password": "x"})

    assert command.status_code == 200
    assert command.json()["injected"] is True
    assert len(command.json()["simulated_commands"]) > 1
    assert ldap.status_code == 200
    assert ldap.json()["injected"] is True
    assert any(item["role"] == "admin" for item in ldap.json()["results"])
    assert xpath.status_code == 200
    assert xpath.json()["injected"] is True
    assert len(xpath.json()["results"]) >= 2


def test_secure_injection_endpoints_reject_or_escape_payloads():
    command = client.get("/command/secure", params={"filename": "image.png; whoami"})
    ldap = client.get("/ldap/secure", params={"username": "*)(|(role=admin))"})
    xpath = client.get("/xpath/secure", params={"username": "' or '1'='1", "password": "x"})

    assert command.status_code == 400
    assert ldap.status_code == 200
    assert ldap.json()["results"] == []
    assert xpath.status_code == 400


def test_cors_vulnerable_reflects_untrusted_origin_and_secure_does_not():
    vulnerable = client.get("/cors/vulnerable", headers={"Origin": "http://evil.example"})
    secure = client.get("/cors/secure", headers={"Origin": "http://evil.example"})

    assert vulnerable.status_code == 200
    assert vulnerable.headers["Access-Control-Allow-Origin"] == "http://evil.example"
    assert vulnerable.headers["Access-Control-Allow-Credentials"] == "true"
    assert secure.status_code == 200
    assert "Access-Control-Allow-Origin" not in secure.headers


def test_ssrf_vulnerable_reaches_simulated_metadata_and_secure_blocks_it():
    vulnerable = client.get("/ssrf/vulnerable", params={"url": "http://169.254.169.254/latest/meta-data"})
    secure = client.get("/ssrf/secure", params={"url": "http://169.254.169.254/latest/meta-data"})

    assert vulnerable.status_code == 200
    assert vulnerable.json()["metadata"]["token"] == "DEMO_METADATA_TOKEN"
    assert secure.status_code == 400


def test_xxe_vulnerable_expands_entity_and_secure_rejects_dtd():
    xml_payload = '<!DOCTYPE data [ <!ENTITY secret SYSTEM "file:///app/secret.txt"> ]><data>&secret;</data>'
    vulnerable = client.post("/xxe/vulnerable", content=xml_payload, headers={"Content-Type": "application/xml"})
    secure = client.post("/xxe/secure", content=xml_payload, headers={"Content-Type": "application/xml"})

    assert vulnerable.status_code == 200
    assert vulnerable.json()["expanded_secret"] == "LAB_XML_SECRET_2026"
    assert secure.status_code == 400


def test_deserialization_vulnerable_trusts_role_and_secure_ignores_it():
    payload = "eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6ImFkbWluIn0="
    vulnerable = client.get("/deserialize/vulnerable", params={"payload": payload})
    secure = client.get("/deserialize/secure", params={"payload": payload})

    assert vulnerable.status_code == 200
    assert vulnerable.json()["is_admin"] is True
    assert secure.status_code == 200
    assert "role" in secure.json()["ignored_fields"]


def test_path_traversal_and_lfi_rfi_vulnerable_read_secret_secure_blocks():
    traversal = client.get("/files/vulnerable", params={"path": "../secrets/app.txt"})
    traversal_secure = client.get("/files/secure", params={"path": "../secrets/app.txt"})
    lfi = client.get("/include/vulnerable", params={"template": "../../secrets/app.txt"})
    rfi = client.get("/include/vulnerable", params={"template": "https://evil.example/template"})
    include_secure = client.get("/include/secure", params={"template": "../../secrets/app.txt"})

    assert traversal.status_code == 200
    assert traversal.json()["content"] == "LAB_FILE_SECRET_2026"
    assert traversal_secure.status_code == 400
    assert lfi.status_code == 200
    assert lfi.json()["type"] == "LFI"
    assert rfi.status_code == 200
    assert rfi.json()["type"] == "RFI"
    assert include_secure.status_code == 400


def test_student_registration_exercises_progress_and_ranking():
    student_id = "student-ranking-test"

    register_response = client.post(
        "/students",
        json={"student_id": student_id, "name": "Student Ranking", "group_name": "G1"},
    )
    exercises_response = client.get("/exercises")
    exercise_response = client.get(
        "/users/vulnerable",
        params={"id": "1 OR 1=1", "student_id": student_id},
    )
    progress_response = client.get("/progress", params={"student_id": student_id})
    ranking_response = client.get("/ranking")
    challenges_response = client.get("/challenges")
    scoreboard_response = client.get("/scoreboard")

    assert register_response.status_code == 200
    assert exercises_response.status_code == 200
    assert any(item["exercise_id"] == "sql_injection_basic" for item in exercises_response.json())
    assert challenges_response.status_code == 200
    assert any(item["info_value"] >= 1 and item["difficulty"] in {"easy", "medium", "hard"} for item in challenges_response.json())
    assert all(not item["exercise_id"].startswith("review_") for item in exercises_response.json())
    assert all("evidence_type" not in item for item in challenges_response.json())
    assert all("validation_keywords" not in item for item in challenges_response.json())
    assert exercise_response.status_code == 200
    assert any(item["exercise_id"] == "sql_injection_basic" for item in progress_response.json())
    assert any(item["student_id"] == student_id and item["points"] >= 10 for item in ranking_response.json())
    assert any(item["student_id"] == student_id and item["information_score"] >= 2 for item in scoreboard_response.json())


def test_student_can_be_identified_by_header():
    student_id = "student-header-test"

    response = client.get(
        "/search/vulnerable",
        params={"q": "<b>test</b>"},
        headers={"X-Student-Id": student_id},
    )
    progress_response = client.get("/progress", params={"student_id": student_id})

    assert response.status_code == 200
    assert any(item["exercise_id"] == "reflected_xss" for item in progress_response.json())


def test_security_headers_challenge_records_progress():
    student_id = "student-csp-test"

    response = client.get("/security-headers", params={"student_id": student_id})
    challenges_response = client.get("/challenges", params={"category": "Security Headers"})
    progress_response = client.get("/progress", params={"student_id": student_id})

    assert response.status_code == 200
    assert "Content-Security-Policy" in response.json()["headers_to_check"]
    assert any(item["exercise_id"] == "csp_headers" for item in challenges_response.json())
    assert any(item["exercise_id"] == "csp_headers" for item in progress_response.json())




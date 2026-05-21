# Security Lab — Bezpieczeństwo aplikacji

Mała aplikacja FastAPI do zajęć z tematu: **Bezpieczeństwo aplikacji, podatności, zewnętrzna autoryzacja, analiza kodu**.

Aplikacja zawiera pary endpointów:

- wariant celowo podatny (`/vulnerable`),
- wariant poprawiony (`/secure`).

Celem jest porównanie błędu i naprawy w lokalnym, kontrolowanym środowisku.

## Uruchomienie

```bash
cd Temat5/security_lab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Po uruchomieniu otwórz:

- http://127.0.0.1:8000
- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/ranking
- http://127.0.0.1:8000/scoreboard
- http://127.0.0.1:8000/challenges

## Uruchomienie przez Docker

```bash
cd Temat5/security_lab
docker compose up --build -d
```

Aplikacja będzie dostępna pod adresem:

- http://127.0.0.1:8000
- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/ranking
- http://127.0.0.1:8000/scoreboard

Dane rankingu są zapisywane w wolumenie Dockera `security-lab-data`. W kontenerze aplikacja używa bazy SQLite zapisanej w `/data/security_lab.db`.

Na serwerze ustaw własne sekrety przez zmienne środowiskowe albo plik `.env`:

```bash
SECURITY_LAB_JWT_SECRET=zmien-to-na-dlugi-losowy-sekret
SECURITY_LAB_PASSWORD_PEPPER=zmien-to-na-drugi-losowy-sekret
```

## Testy

```bash
cd Temat5/security_lab
pytest
```

## Identyfikacja studenta i ranking

Każdy student powinien podawać swój identyfikator podczas wykonywania ćwiczeń. Można to zrobić na dwa sposoby:

1. przez parametr query string `student_id`,
2. przez nagłówek HTTP `X-Student-Id`.

Rejestracja studenta:

```bash
curl -X POST "http://127.0.0.1:8000/students" -H "Content-Type: application/json" -d '{"student_id":"s001","name":"Jan Kowalski","group_name":"G1"}'
```

Lista ćwiczeń:

```bash
curl "http://127.0.0.1:8000/exercises"
```

Pełny katalog wyzwań z poziomem trudności, kategorią, punktami, wskazówką i wartością informacji:

```bash
curl "http://127.0.0.1:8000/challenges"
```

Filtrowanie wyzwań:

```bash
curl "http://127.0.0.1:8000/challenges?difficulty=hard"
curl "http://127.0.0.1:8000/challenges?category=SQL%20Injection"
curl "http://127.0.0.1:8000/challenges?category=Security%20Headers"
```

Postęp konkretnego studenta:

```bash
curl "http://127.0.0.1:8000/progress?student_id=s001"
```

Ranking:

```bash
curl "http://127.0.0.1:8000/ranking"
```

Scoreboard sortowany po wartości zdobytych informacji (`information_score`):

```bash
curl "http://127.0.0.1:8000/scoreboard"
```

`ranking` pokazuje przede wszystkim punkty, a `scoreboard` premiuje studentów, którzy wydobyli bardziej krytyczne informacje, np. schemat bazy albo hashe haseł.

Przykład wykonania ćwiczenia z identyfikatorem studenta:

```bash
curl "http://127.0.0.1:8000/users/vulnerable?id=1%20OR%201=1&student_id=s001"
```

Ten sam przykład z nagłówkiem:

```bash
curl "http://127.0.0.1:8000/users/vulnerable?id=1%20OR%201=1" -H "X-Student-Id: s001"
```

Przykład wykonania wyzwania CSP/nagłówków bezpieczeństwa:

```bash
curl "http://127.0.0.1:8000/security-headers?student_id=s001"
```

Ćwiczenia z dodatkowego katalogu podatności są sprawdzane automatycznie przez aplikację. Student wysyła krótkie `evidence`, a aplikacja porównuje je ze wzorcem wymaganych informacji. Punkty są zapisywane tylko wtedy, gdy odpowiedź pasuje do wzorca:

```bash
curl -X POST "http://127.0.0.1:8000/progress/submit" -H "Content-Type: application/json" -d '{"student_id":"s001","exercise_id":"review_cors_ssrf","evidence":"CORS dotyczy odczytu odpowiedzi przez przeglądarkę, SSRF dotyczy żądań wykonywanych przez serwer backend."}'
```

Jeżeli odpowiedź nie zawiera wymaganych elementów, endpoint zwróci `422` i wskaże brakujące grupy wzorców.

Odpowiedzi, spodziewane obserwacje i opis automatycznej punktacji znajdują się w pliku `TEACHER_NOTES.md`. Ten plik jest przeznaczony dla prowadzącego.

## Wybrane przykłady

SQL Injection — wersja podatna:

```bash
curl "http://127.0.0.1:8000/users/vulnerable?id=1%20OR%201=1"
```

SQL Injection — wersja poprawiona:

```bash
curl "http://127.0.0.1:8000/users/secure?user_id=1"
```

Zamówienia użytkownika — wersja podatna:

```bash
curl "http://127.0.0.1:8000/orders/vulnerable?user_id=2%20OR%201=1"
```

Zamówienia użytkownika — wersja poprawiona:

```bash
curl "http://127.0.0.1:8000/orders/secure?user_id=2"
```

SQL Injection — odczyt hasła jawnego i hasha z bazy:

```bash
curl "http://127.0.0.1:8000/users/vulnerable?id=0%20UNION%20SELECT%20id,password_plain,password_hash%20FROM%20users%20WHERE%20username%20IN%20(%27alice%27,%27charlie%27)"
```

Użytkownicy `alice` i `charlie` mają w danych testowych takie samo hasło jawne, ale różne wartości `password_hash`, ponieważ każdy hash ma osobną losową sól.

XSS — wersja podatna:

```bash
curl "http://127.0.0.1:8000/search/vulnerable?q=%3Cb%3Etest%3C/b%3E"
```

XSS — wersja poprawiona:

```bash
curl "http://127.0.0.1:8000/search/secure?q=%3Cb%3Etest%3C/b%3E"
```

Stored XSS — zapis komentarza w wersji podatnej:

```bash
curl -X POST "http://127.0.0.1:8000/comments/vulnerable" -H "Content-Type: application/json" -d '{"author":"student","content":"<b>zapisany komentarz</b>"}'
curl "http://127.0.0.1:8000/comments/vulnerable"
```

Stored XSS — wersja poprawiona:

```bash
curl -X POST "http://127.0.0.1:8000/comments/secure" -H "Content-Type: application/json" -d '{"author":"student","content":"<b>zapisany komentarz</b>"}'
curl "http://127.0.0.1:8000/comments/secure"
```

DOM-based XSS — porównanie w przeglądarce:

```text
http://127.0.0.1:8000/dom/vulnerable#<b>test</b>
http://127.0.0.1:8000/dom/secure#<b>test</b>
```

CSRF — pobranie demonstracyjnej sesji i tokenu:

```bash
curl -c cookies.txt "http://127.0.0.1:8000/csrf/dev"
```

CSRF — wersja podatna akceptuje żądanie bez tokenu CSRF:

```bash
curl -b cookies.txt -X POST "http://127.0.0.1:8000/transfer/vulnerable" -H "Content-Type: application/json" -d '{"to_account":"PL001234","amount":100}'
```

CSRF — wersja poprawiona wymaga nagłówka `X-CSRF-Token`:

```bash
curl -b cookies.txt -X POST "http://127.0.0.1:8000/transfer/secure" -H "Content-Type: application/json" -H "X-CSRF-Token: TU_WKLEJ_TOKEN" -d '{"to_account":"PL001234","amount":100}'
```

Token użytkownika:

```bash
curl "http://127.0.0.1:8000/token/dev?username=alice"
```

Profil użytkownika:

```bash
curl -H "Authorization: Bearer TU_WKLEJ_TOKEN" "http://127.0.0.1:8000/profile"
```

Panel administratora:

```bash
curl -H "Authorization: Bearer TU_WKLEJ_TOKEN" "http://127.0.0.1:8000/admin"
```

## Analiza kodu

```bash
bandit -r app.py
pip-audit -r requirements.txt
```

## Uwaga

Endpointy z nazwą `vulnerable` są celowo niepoprawne i służą wyłącznie do nauki. Nie przenosimy takiego kodu do aplikacji produkcyjnych.


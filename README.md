# Практична робота №5–7: безпечний мережевий застосунок

Python-клієнт і сервер для Windows та Kali Linux. За замовчуванням застосунок працює через TLS; демонстраційний відкритий TCP обмежено командами `PING`/`ECHO` і треба вмикати явно. Сервер використовує SQLite, bcrypt, JWT, MFA TOTP, контроль ролей, rate limiting і JSONL-журналювання.

Вимоги: Python 3.10 або новіший. Проєкт перевірено користувачем на Kali Linux із Python 3.14.7 та Windows-клієнтом. Залежності зафіксовані на виправлених мінімальних версіях `cryptography 50.0.2` і `pytest 9.2.0`; CI перевіряє Python 3.14 на Ubuntu та Windows.

## Архітектура та файли

| Файл | Призначення |
|---|---|
| `server.py` | TCP/TLS сервер, протокол JSON із 4-байтовим префіксом довжини, SQLite, bcrypt, JWT, ролі, MFA, rate limiting і журналювання (`handle`, `create_user`, `make_server_context`) |
| `client.py` | Консольний клієнт, перевірка CA та SAN, реєстрація, вхід, MFA, передача даних і вихід |
| `generate_cert.py` | Створення самопідписаного сертифіката з DNS/IP SAN (`generate`) |
| `add_user.py` | Локальне створення користувача USER або ADMIN |
| `analyze_logs.py` | Фільтрування JSONL за користувачем, подією та часовим проміжком, підрахунок подій |
| `benchmark.py` | Порівняння пропускної здатності локального TCP echo та TLS echo |
| `tests/test_application.py` | Інтеграційні тести TCP/TLS і механізмів безпеки |
| `.github/workflows/security.yml` | GitHub Actions: pytest, Bandit, pip-audit і збереження звітів |
| `.env.example`, `.gitignore` | Приклад налаштувань та виключення локальних секретів |

Локальні файли `data/`, `logs/`, `.env`, SQLite, ключі та результати benchmark виключені з Git. Облікові дані з попередньої JSON-версії автоматично не мігруються: створіть потрібні записи у SQLite командою `add_user.py`.

## Встановлення

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Kali Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Згенеруйте випадковий секрет JWT (не додавайте його до Git) та внесіть у `.env`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Встановіть `JWT_SECRET` отриманим значенням. Налаштуйте `SERVER_HOST`, `SERVER_PORT`, `APP_DB`, `APP_LOG`, `JWT_TTL_SECONDS`, `LOCK_ATTEMPTS` і `LOCK_SECONDS` у `.env`. Секрет має бути не коротшим за 32 байти. На Windows PowerShell для швидкої генерації можна виконати ту саму Python-команду.

## Приватна мережа VMware: Windows ↔ Kali

Створіть у VMware одну приватну мережу для обох віртуальних вузлів (наприклад, Host-only або одну LAN Segment). У налаштуваннях VM виберіть однакову мережу. Залиште DHCP VMware або призначте в ОС адреси з однієї приватної підмережі, які не конфліктують із DHCP; IP не зашиті в програму. Топологія:

```text
Windows host / VM (client, private IP assigned by VMware)  ── private VMware network ──  Kali VM (server, private IP assigned by VMware)
                                                               TCP port from SERVER_PORT
```

Перевірте адресу вузлів:

```powershell
ipconfig
Test-NetConnection <KALI_PRIVATE_IP> -Port 8443
```

```bash
ip -br address
ip route
ping -c 3 <WINDOWS_PRIVATE_IP>
nc -vz <WINDOWS_PRIVATE_IP> 8443
```

Дозвольте TCP-порт сервера у брандмауері Kali/Windows лише для потрібної приватної підмережі. Запустіть сервер із адресою інтерфейсу Kali або `0.0.0.0`, наприклад `python server.py --host 0.0.0.0 --port 8443`. Визначте IP Kali через `ip -br address`, клієнт використовуватиме його як `--host`.

## TLS і сертифікат

Скрипт створює локальний CA `data/ca.crt` і серверний сертифікат `data/server.crt` із SAN; CA підписує сертифікат сервера, а приватний ключ CA після генерації не зберігається. Клієнт перевіряє ланцюжок до `--ca` та відповідність `--server-name` SAN. Для з'єднання за приватною IP необхідно вказати її як IP SAN. На Kali:

```bash
python generate_cert.py --directory data --dns kali-server --ip <KALI_PRIVATE_IP>
```

Скопіюйте **лише публічний** `data/ca.crt` на Windows довіреним способом; `server.key` залиште на сервері. Клієнт перевіряє, що серверний сертифікат підписаний цим CA, та що його SAN збігається з `--server-name`: `python client.py --host <KALI_PRIVATE_IP> --server-name <KALI_PRIVATE_IP> --ca data/ca.crt`. Якщо використовуєте DNS SAN замість IP SAN, передайте відповідне DNS ім'я для `--server-name`. Для локальної перевірки за замовчуванням SAN `localhost`.

TLS handshake відбувається до прикладного обміну: клієнт надсилає SNI, сторони узгоджують версію та шифр (TLS 1.2+), сервер надсилає сертифікат, а клієнт перевіряє його довіру, строк і SAN. Будь-яка помилка перевірки завершує handshake; перевірка сертифіката не вимикається.

## Сервер, облікові записи та клієнт

На Kali створіть адміністратора локально (пароль не відправляється мережею):

```bash
python add_user.py admin --role ADMIN
```

Запустіть сервер на Kali:

```bash
python server.py --host 0.0.0.0 --port 8443
```

За відсутності сертифіката сервер створить локальний сертифікат `localhost`; для віддаленого клієнта перевипустіть його з IP або DNS SAN як вище. На Windows у другому терміналі створіть звичайний USER через клієнтську реєстрацію або серверну команду `python add_user.py alice` на довіреному адміністраторському вузлі. Запустіть клієнт:

```powershell
python client.py --host <KALI_PRIVATE_IP> --server-name <KALI_PRIVATE_IP> --ca data/ca.crt
```

Консоль пропонує `register`, `login`, `mfa`, `mfa-off`, `send`, `admin`, `logout`, `quit`. Реєстрація через мережу створює лише USER. Команда `admin` доступна лише токену з роллю ADMIN і показує список облікових записів без хешів паролів та MFA-секретів.

## MFA та сесії

Після входу виконайте `mfa`, додайте показаний секрет/URI до застосунку-аутентифікатора і підтвердіть шестицифровим кодом. Наступний вхід видає лише короткоживучий MFA challenge; access JWT повертається після правильного OTP. Код збереженого TOTP-кроку не приймається повторно. Для вимкнення MFA використовується серверна операція `mfa_disable` із чинним JWT та повторною перевіркою OTP. JWT підписується HS256 із секретом `.env`, має `exp`, `jti`, роль і subject; logout додає `jti` до SQLite denylist до завершення терміну.

## Демонстраційний відкритий TCP

Цей режим вимкнений за замовчуванням і призначений тільки для нешкідливого `PING`/`ECHO`. Не передавайте через нього пароль, токен, OTP або персональні дані.

```bash
python server.py --demo-plaintext --host 127.0.0.1 --port 9000
python client.py --demo-plaintext --host 127.0.0.1 --port 9000 --ping
python client.py --demo-plaintext --host 127.0.0.1 --port 9000 --echo "demo"
```

## Безпека та журнали

Паролі зберігаються як bcrypt-хеші у SQLite. Ліміт невдалих входів налаштовується параметрами `LOCK_ATTEMPTS`/`LOCK_SECONDS` (типово 5/300 с) і застосовується за IP та логіном у процесі сервера. JSONL містить лише поля з allow-list; пароль, JWT, OTP, приватний ключ і вміст переданих даних не журналюються. Для аналізу:

```bash
python analyze_logs.py logs/server.jsonl --user alice --event auth.failure --from-time 2026-01-01T00:00:00Z --to-time 2026-12-31T23:59:59Z
```

## Тести та продуктивність

Команди перевірки, покриття вимог і обмеження тестового середовища описані в [TESTING.md](TESTING.md). Запуск тестів:

```bash
python -m pytest -q
python security_checks.py
```

Benchmark запускайте окремо на локальному вузлі; він генерує свіжі реальні вимірювання в CSV, JSON і Markdown:

```bash
python benchmark.py --output benchmark-results --sizes 1024,65536,1048576 --repeats 5
```

Тест вимірює echo передачу однакових обсягів байтів, включно з часом встановлення TCP/TLS з'єднання; це показовий локальний вимір, а не прогноз продуктивності VMware/Kali. TLS має додаткову вартість handshake і криптографічної обробки; фактичні значення залежать від платформи. Якщо сертифікат перехоплює локальний TLS-посередник, артефакти містять TCP вимірювання та `blocked` для TLS, без вимикання перевірки сертифіката. Для порівняння запустіть benchmark на Kali або Windows вузлі без такого перехоплення.

## GitHub Actions

Workflow `.github/workflows/security.yml` запускає pytest, Bandit і pip-audit при `push` та `pull_request` на Ubuntu і Windows з Python 3.14. Провал тестів, знахідки Bandit рівня Medium або вище чи вразливості pip-audit завершують job помилкою. JUnit XML та звіти сканерів завантажуються як окремі artifacts для кожної ОС. Фактичний CI статус з'явиться лише після запуску workflow на GitHub.

## Перелік знімків екрана для звіту

1. Налаштування однакової приватної мережі VMware для Windows і Kali.
2. Вивід IP-адрес обох вузлів і успішний `Test-NetConnection`/`nc`.
3. Запущений TLS сервер із адресою/портом.
4. Успішна TLS-перевірка сертифіката та клієнтський запит.
5. Відхилення сертифіката з невідповідним SAN.
6. Успішний і невдалий вхід, а також заборона USER для ADMIN-функції.
7. Налаштування MFA та вхід із OTP.
8. Подія блокування після невдалих входів.
9. Результат pytest і звіти GitHub Actions.
10. Таблиця та файли локального benchmark.

## Де реалізовано десять пунктів роботи

1. Мережа: аргументи `server.py`/`client.py`, `.env.example`, розділ VMware вище.
2. TCP і відкритий demo: `server.handle` для `ping`/`echo`, `--demo-plaintext` у сервері та клієнті.
3. TLS: `generate_cert.generate` (локальний CA та SAN-серверний сертифікат), `server.make_server_context`, `client.request` (CERT_REQUIRED/hostname).
4. Облікові записи/ролі: `server._db`, `server.create_user`, bcrypt, `add_user.py`, `admin_status`.
5. JWT/сесії: `_mint_token`, `_decode_token`, `logout`, SQLite `revoked_tokens`.
6. Журналювання/аналіз: `log_event`, `analyze_logs.read_events` і CLI-фільтри.
7. Brute force: `_failures`, `LOCK_ATTEMPTS`, `LOCK_SECONDS`, `test_wrong_password_and_lock_expiry`.
8. MFA: операції `mfa_enroll`, `mfa_enable`, `mfa_verify`, `mfa_disable` у `handle` та відповідний тест.
9. CI/CD: `.github/workflows/security.yml`.
10. Перевірки й вимірювання: `tests/test_application.py`, `security_checks.py`, `benchmark.py`.

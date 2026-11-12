# Перевірка проєкту

## Підготовка

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Потрібен Python 3.10+; рекомендоване середовище для цієї роботи — Python 3.14.7. Встановіть випадковий `JWT_SECRET` довжиною від 32 байтів у `.env`. На Kali:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example .env
```

## Автоматизовані тести

```bash
python -m pytest -q
python security_checks.py
```

Тести створюють SQLite-бази, сертифікати й журнали у `.pytest-tmp`; жодні реальні облікові записи чи журнали не використовуються. Інтеграційний TLS-сервер слухає лише `127.0.0.1` на випадковому вільному порту. `pytest.ini` задає цей каталог, щоб ізольоване тестування не залежало від системного Temp.

Усі тести є справжніми перевірками: помилка сертифіката завершує тест невдачею, автоматичного `skip` для TLS немає. Якщо локальний TLS-перехоплювач підмінює сертифікат loopback-з'єднання, TLS-інтеграційні тести мають упасти. Повторіть повний набір на Kali або CI без такого посередника; не вимикайте перевірку сертифіката.

Перевірки `tests/test_application.py`:

- TCP/TLS та успішна перевірка довіреного сертифіката.
- Відхилення недовіреного сертифіката і неправильного SAN.
- bcrypt-вхід з правильним/неправильним паролем.
- Короткочасне блокування після налаштованої кількості спроб і відновлення після його завершення.
- Заборона USER для ADMIN-операції.
- Підпис JWT, підроблений і прострочений JWT, відсутній токен та відкликання після logout.
- Передача даних із SHA-256 та відхилення неправильного digest.
- Видача MFA challenge без access JWT, перевірка OTP і відхилення повторного TOTP-коду.
- Демонстраційні TCP PING/ECHO без доступу до автентифікації.
- JSONL-події та відсутність відкритих паролів у журналі.

Для окремої перевірки логів із фільтрами:

```bash
python analyze_logs.py logs/server.jsonl --user alice --event auth.failure --from-time 2026-01-01T00:00:00Z --to-time 2026-12-31T23:59:59Z --output logs/filtered.md
```

## Ручна мережева перевірка Windows–Kali

1. Переконайтеся, що обидві VM підключені до тієї самої приватної мережі VMware.
2. Подивіться IP через `ipconfig` (Windows) і `ip -br address` (Kali).
3. На Kali створіть TLS сертифікат із фактичною IP у SAN: `python generate_cert.py --directory data --ip <KALI_PRIVATE_IP>`.
4. Скопіюйте публічний `data/ca.crt` на Windows, але не копіюйте приватний ключ сервера.
5. Запустіть сервер: `python server.py --host 0.0.0.0 --port 8443`.
6. З Windows виконайте `Test-NetConnection <KALI_PRIVATE_IP> -Port 8443`, потім запустіть `python client.py --host <KALI_PRIVATE_IP> --server-name <KALI_PRIVATE_IP> --ca data/ca.crt`.
7. Спробуйте інший `--server-name`: клієнт має відхилити SAN mismatch.
8. Перевірте реєстрацію USER, ADMIN-команду, надсилання тексту, logout і MFA.

Відкритий TCP перевіряється лише локально без секретів:

```bash
python server.py --demo-plaintext --host 127.0.0.1 --port 9000
python client.py --demo-plaintext --host 127.0.0.1 --port 9000 --ping
python client.py --demo-plaintext --host 127.0.0.1 --port 9000 --echo demo
```

## Аналіз безпеки

Залежності безпеки оновлені до виправлених сумісних версій: `cryptography>=50.0.2,<51` і `pytest>=9.2.0,<10`. Встановіть scanners та запустіть перевірки:

```bash
pip install bandit pip-audit
bandit -r . -x .venv,tests -ll
pip-audit -r requirements.txt
```

`pip-audit` потребує доступу до індексу пакетів і довіреного TLS-з'єднання для актуальних даних про вразливості. У GitHub Actions pytest, Bandit і pip-audit запускаються при push/pull request на Ubuntu та Windows із Python 3.14; JUnit і JSON-звіти зберігаються як artifacts для кожної ОС. Будь-яка вразливість pip-audit, Bandit Medium+ або невдалий тест завершує job помилкою.

## Benchmark

```bash
python benchmark.py --output benchmark-results --sizes 1024,65536,1048576 --repeats 5
```

Ця команда є рекомендованим повторним запуском на Kali. Вона виконує п'ять повних з'єднань на кожен розмір для обох режимів; часовий інтервал охоплює встановлення TCP/TLS з'єднання і передачу з перевіркою однакової кількості байтів. Після завершення перевірте `benchmark-results/benchmark.csv`, `benchmark.json` і `benchmark.md`.

Скрипт передає однаковий payload через локальні TCP і TLS echo-сервери, перевіряє кількість отриманих байтів і створює `benchmark.csv`, `benchmark.json`, `benchmark.md`. У Markdown наведено швидкість і відсоткову різницю середнього часу. Це локальні результати конкретного запуску; вони не екстраполюються на мережу VMware. Зробіть знімок таблиці та збережіть усі три файли у звітні матеріали.

## Критерії проходження

- `pytest` повернув код 0.
- `security_checks.py` повідомив про успішне відхилення сертифіката та hostname mismatch.
- Немає секретів/приватних ключів у Git status або артефактах звіту.
- `benchmark-results` містить CSV, JSON і Markdown, створені актуальним запуском.
- GitHub Actions завершився успішно після проходження тестів і сканерів; цей пункт підтверджується лише у GitHub Actions UI.

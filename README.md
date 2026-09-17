# Информационная безопасность
## Лабораторная работа №1
### Стек

- Java 17 и Maven;
- Javalin 7;
- SQLite и JDBC;
- bcrypt (`jBCrypt`) для хэширования паролей;
- JWT (`java-jwt`) для аутентификации;
- OWASP Java Encoder для экранирования пользовательских данных;
- SpotBugs для SAST;
- OWASP Dependency-Check для SCA.

## Архитектура

```text
src/main/java/ru/itmo
├── App.java                 # точка входа
├── config/                  # настройки, сборка приложения и БД
├── controller/              # обработчики HTTP-запросов
├── dto/                     # модели запросов и ответов API
├── exception/               # прикладные исключения
├── handler/                 # единая обработка ошибок
├── middleware/              # JWT-проверка и security-заголовки
├── model/                   # доменные модели
├── repository/              # интерфейс и SQLite-реализация доступа к данным
├── routing/                 # маршруты приложения
├── security/                # JWT и безопасное кодирование вывода
└── service/                 # бизнес-логика регистрации и входа
```

### API

Все тела запросов и ответов передаются в JSON. Для POST-запросов требуется заголовок `Content-Type: application/json`.

### `POST /auth/register`

Создаёт пользователя. Логин должен содержать 3–32 символа из набора `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`. Пароль должен содержать 12–72 символа, хотя бы одну прописную букву, одну строчную букву и одну цифру.

Запрос:

```bash
curl -i -X POST http://localhost:7070/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"login":"student","password":"StrongPass123"}'
```

Успешный ответ — `201 Created`:

```json
{
  "message": "User registered",
  "login": "student"
}
```

Возможные ошибки: `400 Bad Request` при неверном формате данных и `409 Conflict`, если логин уже занят.

### `POST /auth/login`

Проверяет логин и пароль и выдаёт JWT со сроком действия 15 минут.

Запрос:

```bash
curl -i -X POST http://localhost:7070/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"student","password":"StrongPass123"}'
```

Успешный ответ — `200 OK`:

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

При неверном логине или пароле API возвращает одинаковый ответ `401 Unauthorized`, не раскрывая, существует ли пользователь.

Токен удобно получить в переменную при наличии `jq`:

```bash
TOKEN=$(curl -s -X POST http://localhost:7070/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"student","password":"StrongPass123"}' | jq -r .accessToken)
```

### `GET /api/data`

Возвращает демонстрационный список данных. Это защищённый эндпоинт: JWT нужно передать по схеме Bearer.

```bash
curl -i http://localhost:7070/api/data \
  -H "Authorization: Bearer $TOKEN"
```

Успешный ответ — `200 OK`:

```json
{
  "requestedBy": "student",
  "items": [
    {"id": 1, "title": "Parameterized SQL queries"},
    {"id": 2, "title": "JWT authentication"},
    {"id": 3, "title": "Escaped API output"}
  ]
}
```

Без токена запрос отклоняется:

```bash
curl -i http://localhost:7070/api/data
```

Ответ — `401 Unauthorized`:

```json
{"message":"Bearer token is required"}
```

Просроченный, повреждённый или подписанный другим ключом токен также приводит к `401 Unauthorized`.

## Реализованные меры защиты

### Защита от SQL-инъекций

- Любой пользовательский ввод передаётся в SQLite только через `PreparedStatement` и параметры `?`.
- Значения устанавливаются методами `setString`; SQL-запросы не собираются конкатенацией строк.
- Работа с БД сосредоточена в `SqliteUserRepository`, поэтому контроллеры и сервисы не выполняют SQL напрямую.
- Структура БД создаётся статическим запросом без пользовательских значений.
- Интеграционный тест отправляет логин `' OR 1=1 --` и проверяет, что аутентификация завершается ответом `401`, а не обходится.

Пример безопасного запроса из репозитория:

```java
private static final String SELECT_BY_LOGIN =
        "SELECT login, password_hash FROM users WHERE login = ?";

PreparedStatement statement = connection.prepareStatement(SELECT_BY_LOGIN);
statement.setString(1, login);
```

### Защита от XSS

- API всегда возвращает JSON, а не формирует HTML из пользовательского ввода.
- Значения, полученные от пользователя и возвращаемые в ответе (`login`, имя аутентифицированного пользователя и сообщения ошибок), проходят контекстное экранирование `Encode.forHtmlContent` из OWASP Java Encoder.
- Формат логина ограничен безопасным allowlist-регулярным выражением и не допускает `<`, `>`, кавычки и пробельные символы.
- Каждый ответ получает заголовки `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` и `X-Content-Type-Options: nosniff`.
- Клиентскому приложению всё равно следует вставлять строки как текст (`textContent`), а не как HTML (`innerHTML`): защита API дополняет, но не заменяет безопасный рендеринг на клиенте.

### Защита аутентификации

- Пароли никогда не сохраняются в открытом виде: перед записью они хэшируются bcrypt с cost factor `12` и индивидуальной солью.
- База данных содержит только логин и bcrypt-хэш. Интеграционный тест отдельно проверяет, что сохранённое значение отличается от пароля и имеет формат bcrypt.
- Для существующего и несуществующего пользователя используется одинаковое сообщение `Invalid login or password`.
- При неизвестном логине выполняется проверка фиктивного bcrypt-хэша, что уменьшает различие во времени ответа и затрудняет перебор имён пользователей.
- После успешного входа выдаётся JWT, подписанный `HMAC-SHA-256`. В токен включены `iss=secure-api`, `sub=<login>`, время выпуска и срок истечения 900 секунд.
- Секрет подписи читается из `JWT_SECRET` и валидируется: длина должна быть не меньше 32 символов. Секрет не хранится в исходном коде.
- Middleware применяется ко всем маршрутам `/api/*`, извлекает заголовок `Authorization: Bearer ...`, проверяет подпись, issuer и срок действия токена. Обработчик контроллера запускается только после успешной проверки.
- Ответы содержат `Cache-Control: no-store`, чтобы токены и приватные данные не сохранялись промежуточными кэшами.

### Дополнительные меры

- Максимальный размер тела HTTP-запроса ограничен 16 КиБ.
- Ошибки обрабатываются централизованно. Клиент не получает stack trace, текст SQL или внутренние сведения о БД.
- Файлы `.env`, `*.db` и результаты сборки исключены из Git.
- Автотесты проверяют полный сценарий регистрации и входа, запрет анонимного доступа, неверный JWT, SQLi-строку, валидацию данных и отсутствие открытого пароля в БД.

## CI/CD и security-сканирование

Workflow находится в `.github/workflows/ci.yml` и запускается автоматически при каждом `push` и создании или обновлении `pull request`. Права workflow ограничены чтением содержимого репозитория.

Pipeline содержит две независимые проверки:

1. `Tests and SpotBugs SAST` запускает JUnit-тесты и SpotBugs с `effort=Max`, `threshold=Low`, `failOnError=true`. HTML-отчёт публикуется как artifact `spotbugs-report`, даже если проверка завершилась ошибкой.
2. `OWASP dependency scan (SCA)` проверяет прямые и транзитивные Maven-зависимости через OWASP Dependency-Check. Сборка завершается ошибкой при уязвимости с CVSS не ниже 7. HTML- и JSON-отчёты публикуются как artifact `dependency-check-reports`.

При первом CI-запуске SCA обнаружил в `sqlite-jdbc 3.50.3.0` уязвимости `CVE-2026-11822`, `CVE-2026-11824` и `CVE-2025-70873` с CVSS 7.5–8.5. Зависимость обновлена до `3.53.4.0`; повторная локальная проверка завершилась успешно и не обнаружила уязвимых зависимостей. Порог проверки не отключался, а CVE не добавлялись в suppression-файл.

Для ускорения и повышения стабильности загрузки данных NVD рекомендуется добавить в настройках GitHub репозитория secret `NVD_API_KEY`. Значение передаётся сканеру через переменную окружения и не выводится в репозиторий.

Локально те же проверки запускаются командами:

```bash
mvn clean test
mvn compile spotbugs:check
mvn org.owasp:dependency-check-maven:check
```

### SAST — SpotBugs в GitHub Actions

<!-- ACTIONS_SAST_SCREENSHOT -->

_Здесь должен находиться скриншот успешного job `Tests and SpotBugs SAST` из GitHub Actions._

### SCA — OWASP Dependency-Check в GitHub Actions

<!-- ACTIONS_SCA_SCREENSHOT -->

_Здесь должен находиться скриншот успешного job `OWASP dependency scan (SCA)` из GitHub Actions._

После запуска отчёты можно скачать на странице конкретного workflow run в секции **Artifacts**. Локальные копии отчётов Maven создаются в `target/reports/spotbugs.html`, `target/dependency-check-report.html` и `target/dependency-check-report.json`.

## Тестирование вручную

Минимальный позитивный сценарий:

```bash
# 1. Регистрация — ожидается 201
curl -i -X POST http://localhost:7070/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"login":"student","password":"StrongPass123"}'

# 2. Вход — ожидается 200 и JWT
TOKEN=$(curl -s -X POST http://localhost:7070/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"student","password":"StrongPass123"}' | jq -r .accessToken)

# 3. Доступ с JWT — ожидается 200
curl -i http://localhost:7070/api/data \
  -H "Authorization: Bearer $TOKEN"

# 4. Доступ без JWT — ожидается 401
curl -i http://localhost:7070/api/data
```

Автоматические тесты:

```bash
mvn clean test
```

Тесты поднимают приложение на случайном свободном порту и используют временную SQLite-базу, поэтому не изменяют локальную рабочую БД.

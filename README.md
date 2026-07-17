# SSO
[![sso-ci](https://github.com/iosdevsx/sso/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/iosdevsx/sso/actions/workflows/go.yml)

gRPC-сервис регистрации и аутентификации. Выдаёт пару access (JWT) + refresh
token, умеет ротацию refresh-токенов, logout и защиту от перебора паролей.
Контракт живёт в отдельном репозитории [protos](https://github.com/iosdevsx/protos).

## API

| RPC | Что делает |
|---|---|
| `Register(email, password)` | создаёт пользователя, возвращает id |
| `Login(email, password)` | проверяет пароль, возвращает пару access + refresh |
| `Refresh(refresh_token)` | обменивает живой refresh на новую пару (старый гасится) |
| `Logout(refresh_token)` | отзывает refresh; идемпотентен |

Маппинг ошибок: невалидный ввод — `InvalidArgument`, занятый email —
`AlreadyExists`, неверные credentials и мёртвый refresh — `Unauthenticated`,
превышение попыток входа — `ResourceExhausted`. Внутренние ошибки наружу не
протекают — клиент получает `Internal` без деталей, подробности остаются в
логах сервера.

## Что внутри

**Пароли.** Argon2id (19 MiB, t=2, p=1 — параметры зашиты в `hasher.New()`,
в БД хранится PHC-строка). Перед хешированием пароль нормализуется в Unicode
NFC, границы длины — 12–128 символов, composition rules нет (NIST SP 800-63B).

**Email.** Валидируется через `net/mail` плюс продуктовые правила (без display
name, точка в домене, ASCII, ≤254 байт). В базе хранится каноническая форма
(trim + lowercase), уникальность — по ней: `Alice@example.com` и
`alice@example.com` — один аккаунт.

**Access token.** JWT HS256, claims — только `sub`, `iat`, `exp`. TTL 15 минут.

**Refresh token.** 32 байта из `crypto/rand`, клиент получает base64url-строку,
в базе лежит только SHA-256. Одноразовый: `Refresh` атомарно гасит предъявленный
токен (`UPDATE … WHERE revoked_at IS NULL AND expires_at > now() RETURNING`) и
выдаёт новый — параллельные запросы с одним токеном не проходят оба.

**Защита от перебора.** 5 неудачных попыток входа блокируют аккаунт на
15 минут (атомарный UPSERT-счётчик в PostgreSQL). Пока блокировка активна,
пароль не проверяется. Ответ «юзер не найден» выравнивается по времени с
«неверным паролем» фиктивной проверкой Argon2id — по латентности логина нельзя
понять, существует ли аккаунт.

Слои классические: `grpc handler → service → storage`. Ошибки поднимаются
через `%w` и различаются `errors.Is`; gRPC-коды знает только transport,
доменные ошибки — только service, `pgx.ErrNoRows` не выходит за storage.

## Запуск

Нужны Docker и заполненный `.env` в корне (см. переменные ниже):

```bash
docker compose up -d --build
```

Поднимет PostgreSQL и сервис на `localhost:44044`. Миграции применяются
автоматически при старте (golang-migrate, embedded).

Переменные `.env`:

```
CONFIG_PATH=config/docker.yaml
SSO_POSTGRES_USER=...
SSO_POSTGRES_PASSWORD=...
SSO_POSTGRES_DB=...
SSO_TOKEN_SECRET=...   # openssl rand -base64 48
```

Не-секретная конфигурация (TTL токенов, лимиты попыток, порты) — в
`config/local.yaml` и `config/docker.yaml`.

## Разработка

```bash
make build         # GOWORK=off go build ./...
make test          # сборка + все тесты
make migrate-new name=add_something   # новая пара up/down миграций
```

Сервис разрабатывается в go workspace вместе с репозиторием protos, поэтому
сборка и тесты идут с `GOWORK=off` — это гарантирует, что `go.mod` честный и
проект собирается вне workspace.

Ручная проверка всех сценариев — `./requests.sh` (нужны grpcurl и jq):
регистрация с граничными случаями, логин, полный цикл ротации refresh-токена,
logout, идемпотентность. Reflection включён, так что grpcurl работает без
proto-файлов.

## Структура

```
cmd/sso/            точка входа, сборка зависимостей
internal/config/    cleanenv: YAML + env
internal/grpc/auth/ gRPC handlers, маппинг ошибок в коды
internal/service/auth/  бизнес-логика: валидация, login flow, токены
internal/storage/postgres/  репозиторий на pgx
internal/lib/       hasher (argon2id), jwt, slog-хелперы
migrations/         golang-migrate, применяются на старте
```

## Что осознанно не сделано

- Подтверждение email — контракт готов, реализация отложена.
- Anti-enumeration: `Register` честно отвечает `AlreadyExists`.
- Отзыв access-токенов до истечения (JWT stateless, TTL короткий).
- `app_id`/audience — до появления второго приложения-потребителя.

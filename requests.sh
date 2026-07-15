#!/usr/bin/env bash
# grpcurl-сценарии проверки SSO (сервис поднят: порт 44044).
# Запуск целиком: ./requests.sh — или копируй команды по одной.

HOST=localhost:44044
SVC=sso.v1.AuthService

echo "=== REGISTER ==="

echo "--- 1. Валидная регистрация -> user_id ---"
grpcurl -plaintext -d '{
  "email": "  Alice+Work@Example.COM  ",
  "password": "correct horse battery staple"
}' $HOST $SVC/Register

echo "--- 2. Тот же email в другом регистре -> AlreadyExists ---"
grpcurl -plaintext -d '{
  "email": "ALICE+work@example.com",
  "password": "another-valid-password"
}' $HOST $SVC/Register

echo "--- 3. Display name -> InvalidArgument ---"
grpcurl -plaintext -d '{
  "email": "Alice <alice2@example.com>",
  "password": "correct horse battery staple"
}' $HOST $SVC/Register

echo "--- 4. Домен без точки -> InvalidArgument ---"
grpcurl -plaintext -d '{
  "email": "user@localhost",
  "password": "correct horse battery staple"
}' $HOST $SVC/Register

echo "--- 5. Кириллица в адресе -> InvalidArgument ---"
grpcurl -plaintext -d '{
  "email": "юзер@example.com",
  "password": "correct horse battery staple"
}' $HOST $SVC/Register

echo "--- 6. Пароль 11 символов -> InvalidArgument (too short) ---"
grpcurl -plaintext -d '{
  "email": "bob@example.com",
  "password": "elevenchars"
}' $HOST $SVC/Register

echo "--- 7. Пароль 129 символов -> InvalidArgument (too long) ---"
grpcurl -plaintext -d "{
  \"email\": \"bob@example.com\",
  \"password\": \"$(printf 'a%.0s' {1..129})\"
}" $HOST $SVC/Register

echo "--- 8. Пароль 100 символов -> УСПЕХ (bcrypt-лимит 72 снят) ---"
grpcurl -plaintext -d "{
  \"email\": \"bob@example.com\",
  \"password\": \"$(printf 'a%.0s' {1..100})\"
}" $HOST $SVC/Register

echo "=== LOGIN ==="

echo "--- 9. Валидный логин (canonical: регистр/пробелы не мешают) -> ПАРА token + refresh_token ---"
grpcurl -plaintext -d '{
  "email": " ALICE+work@Example.com ",
  "password": "correct horse battery staple"
}' $HOST $SVC/Login

echo "--- 10. Неверный пароль -> Unauthenticated: invalid credentials ---"
grpcurl -plaintext -d '{
  "email": "alice+work@example.com",
  "password": "wrong-password-guess"
}' $HOST $SVC/Login

echo "--- 11. Несуществующий email -> Unauthenticated: invalid credentials ---"
grpcurl -plaintext -d '{
  "email": "ghost@example.com",
  "password": "correct horse battery staple"
}' $HOST $SVC/Login
echo "=== REFRESH-ЦИКЛ (нужен jq) ==="

echo "--- 12. Login -> берём refresh из ответа ---"
RT=$(grpcurl -plaintext -d '{
  "email": "alice+work@example.com",
  "password": "correct horse battery staple"
}' $HOST $SVC/Login | jq -r .refreshToken)
echo "got refresh: ${RT:0:8}..."

echo "--- 13. Refresh -> новая пара ---"
RT2=$(grpcurl -plaintext -d "{\"refresh_token\": \"$RT\"}" $HOST $SVC/Refresh | tee /dev/stderr | jq -r .refreshToken)

echo "--- 14. Повторный Refresh со СТАРЫМ токеном -> Unauthenticated (ротация!) ---"
grpcurl -plaintext -d "{\"refresh_token\": \"$RT\"}" $HOST $SVC/Refresh

echo "--- 15. Logout с новым токеном -> OK ---"
grpcurl -plaintext -d "{\"refresh_token\": \"$RT2\"}" $HOST $SVC/Logout

echo "--- 16. Refresh после Logout -> Unauthenticated ---"
grpcurl -plaintext -d "{\"refresh_token\": \"$RT2\"}" $HOST $SVC/Refresh

echo "--- 17. Повторный Logout мёртвым токеном -> OK (идемпотентность) ---"
grpcurl -plaintext -d "{\"refresh_token\": \"$RT2\"}" $HOST $SVC/Logout

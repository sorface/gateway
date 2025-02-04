# Security Gateway

Шлюз безопасности платформы Sorface

## Технологический стек

* Kotlin (2.2.1)
* Spring (3.3.4)
* Spring Security (oauth2-client, oauth2-resource-server)

# Environment

## Cors

| Environment            | Описание                                | Store     |
|------------------------|-----------------------------------------|-----------|
| CORS_ALLOWED_ORIGINS   | Разрешенные источники                   | ConfigMap |
| CORS_ALLOWED_METHODS   | Разрешенные методы                      | ConfigMap |
| CORS_ALLOWED_HEADERS   | Разрешенные заголовки                   | ConfigMap |
| CORS_ALLOW_CREDENTIALS | Разрешение использования учетных данных | ConfigMap |

## Redis

| Environment    | Описание               | Store |
|----------------|------------------------|-------|
| REDIS_HOST     | Хост Redis             | Vault |
| REDIS_USERNAME | Имя пользователя Redis | Vault |
| REDIS_PASSWORD | Пароль Redis           | Vault |
| REDIS_PORT     | Порт Redis             | Vault |

## Cookie

| Environment                      | Описание                                         | Store     |
|----------------------------------|--------------------------------------------------|-----------|
| GATEWAY_SESSION_COOKIE_DOMAIN    | Домен куки сессии шлюза                          | ConfigMap |
| GATEWAY_SESSION_COOKIE_NAME      | Имя куки сессии шлюза                            | ConfigMap |
| GATEWAY_SESSION_COOKIE_HTTP_ONLY | Только HTTP для куки сессии шлюза                | ConfigMap |
| GATEWAY_SESSION_COOKIE_PATH      | Путь куки сессии шлюза                           | ConfigMap |
| GATEWAY_SESSION_COOKIE_SECURE    | Безопасность куки сессии шлюза                   | ConfigMap |
| GATEWAY_SESSION_COOKIE_SAME_SITE | Политика одинакового сайта для куки сессии шлюза | ConfigMap |

## Routes

| Environment           | Описание                        | Store     |
|-----------------------|---------------------------------|-----------|
| GATEWAY_SERVICE_URL   | URL шлюза                       | ConfigMap |
| INTERVIEW_SERVICE_URL | URL службы сервера для интервью | ConfigMap |
| PASSPORT_SERVICE_URL  | URL службы паспортов            | ConfigMap |

## OAuth2 (IDP)

| Environment            | Описание                                      | Store |
|------------------------|-----------------------------------------------|-------|
| PASSPORT_CLIENT_ID     | ID клиента службы авторизации IDP             | Vault |
| PASSPORT_CLIENT_SECRET | Секретный ключ клиента службы авторизации IDP | Vault |

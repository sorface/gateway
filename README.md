# Security Gateway

Шлюз безопасности платформы Sorface

## Технологический стек

* Kotlin (2.2.1)
* Spring (3.3.4) (Security, Redis)

## Environment

### Cors

| Environment            | Описание                                | Store     | Значение DEV/PROD                                                                                                                                              |
|------------------------|-----------------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CORS_ALLOWED_ORIGINS   | Разрешенные источники                   | ConfigMap | [http://localhost:9030;http://localhost:3000;http://localhost:9020;http://localhost:8080]<br/> / <br/> [https://id.sorface.com, https://interview.sorface.com] |
| CORS_ALLOWED_METHODS   | Разрешенные методы                      | ConfigMap | * / *                                                                                                                                                          |
| CORS_ALLOWED_HEADERS   | Разрешенные заголовки                   | ConfigMap | * / *                                                                                                                                                          |
| CORS_ALLOW_CREDENTIALS | Разрешение использования учетных данных | ConfigMap | true / true                                                                                                                                                    |

### Redis

| Environment    | Описание               | Store | Значение DEV/PROD  |
|----------------|------------------------|-------|--------------------|
| REDIS_HOST     | Хост Redis             | Vault | localhost / ...    |
| REDIS_USERNAME | Имя пользователя Redis | Vault | default / ...      |
| REDIS_PASSWORD | Пароль Redis           | Vault | testpassword / ... |
| REDIS_PORT     | Порт Redis             | Vault | 6379 / ...         |

### Cookie

| Environment                      | Описание                                         | Store     | Значение DEV/PROD        |
|----------------------------------|--------------------------------------------------|-----------|--------------------------|
| GATEWAY_SESSION_COOKIE_DOMAIN    | Домен куки сессии шлюза                          | ConfigMap | localhost / .sorface.com |
| GATEWAY_SESSION_COOKIE_NAME      | Имя куки сессии шлюза                            | ConfigMap | gtw_sid / gtw_sid        |
| GATEWAY_SESSION_COOKIE_HTTP_ONLY | Только HTTP для куки сессии шлюза                | ConfigMap | true / true              |
| GATEWAY_SESSION_COOKIE_PATH      | Путь куки сессии шлюза                           | ConfigMap | '/' / '/'                |
| GATEWAY_SESSION_COOKIE_SECURE    | Безопасность куки сессии шлюза                   | ConfigMap | true / true              |
| GATEWAY_SESSION_COOKIE_SAME_SITE | Политика одинакового сайта для куки сессии шлюза | ConfigMap | lax  / lax               |

### Routes

| Environment           | Описание                        | Store     | Значение DEV/PROD                                    |
|-----------------------|---------------------------------|-----------|------------------------------------------------------|
| GATEWAY_SERVICE_URL   | URL шлюза                       | ConfigMap | localhost:9000 / https://gateway.sorface.com         |
| INTERVIEW_SERVICE_URL | URL службы сервера для интервью | ConfigMap | localhost:5043 / внутренний сервис backend-interview |
| PASSPORT_SERVICE_URL  | URL службы паспортов            | ConfigMap | localhost:8080 / https://api.passport.sorface.com    |

### OAuth2 (IDP)

| Environment            | Описание                                      | Store |
|------------------------|-----------------------------------------------|-------|
| PASSPORT_CLIENT_ID     | ID клиента службы авторизации IDP             | Vault |
| PASSPORT_CLIENT_SECRET | Секретный ключ клиента службы авторизации IDP | Vault |

## Production

URL развертывания: https://gateway.sorface.com

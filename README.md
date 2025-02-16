# Security Gateway

Шлюз безопасности платформы Sorface

## Технологический стек

* Kotlin (2.2.1)
* Spring (3.3.4)
  * Security
  * session-redis-data
  * gateway

## Environment

### Application Metadata

| Environment                  | Описание          | Store     | Значение DEV ~ PROD                | Тип данных |
|------------------------------|-------------------|-----------|------------------------------------|------------|
| APPLICATION_METADATA_VERSION | Версия приложения | ConfigMap | `1.0.0`' ~ `BUILD_CURRENT_VERSION` | string     |
| APPLICATION_TARGET_PORT      | Порт запуска      | ConfigMap | `9000`' ~ `...`                    | integer    |

### Cors

| Environment            | Описание                                | Store     | Значение DEV ~ PROD                                                                                                                                  | Тип данных |
|------------------------|-----------------------------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| CORS_ALLOWED_ORIGINS   | Разрешенные источники                   | ConfigMap | `http://localhost:9030;http://localhost:3000;http://localhost:9020;http://localhost:8080]` ~ `https://id.sorface.com, https://interview.sorface.com` | string     |
| CORS_ALLOWED_METHODS   | Разрешенные методы                      | ConfigMap | `*` ~ `*`                                                                                                                                            | string     |
| CORS_ALLOWED_HEADERS   | Разрешенные заголовки                   | ConfigMap | `*` ~ `*`                                                                                                                                            | string     |
| CORS_ALLOW_CREDENTIALS | Разрешение использования учетных данных | ConfigMap | `true` ~ `true`                                                                                                                                      | boolean    |

### Redis

| Environment    | Описание               | Store | Значение DEV ~ PROD    | Тип данных |
|----------------|------------------------|-------|------------------------|------------|
| REDIS_HOST     | Хост Redis             | Vault | `localhost` ~ `...`    | string     |
| REDIS_USERNAME | Имя пользователя Redis | Vault | `default` ~ `...`      | string     |
| REDIS_PASSWORD | Пароль Redis           | Vault | `testpassword` ~ `...` | string     |
| REDIS_PORT     | Порт Redis             | Vault | `6379` ~ `...`         | integer    |

### Cookie

| Environment                      | Описание                                         | Store     | Значение DEV ~ PROD         | Тип данных |
|----------------------------------|--------------------------------------------------|-----------|-----------------------------|------------|
| GATEWAY_SESSION_COOKIE_DOMAIN    | Домен куки сессии шлюза                          | ConfigMap | `localhost` ~ `sorface.com` | string     |
| GATEWAY_SESSION_COOKIE_NAME      | Имя куки сессии шлюза                            | ConfigMap | `gtw_sid` ~ `gtw_sid`       | string     |
| GATEWAY_SESSION_COOKIE_HTTP_ONLY | Только HTTP для куки сессии шлюза                | ConfigMap | `true` ~ `true`             | boolean    |
| GATEWAY_SESSION_COOKIE_PATH      | Путь куки сессии шлюза                           | ConfigMap | `/` ~ `/`                   | string     |
| GATEWAY_SESSION_COOKIE_SECURE    | Безопасность куки сессии шлюза                   | ConfigMap | `true` ~ `true`             | boolean    |
| GATEWAY_SESSION_COOKIE_SAME_SITE | Политика одинакового сайта для куки сессии шлюза | ConfigMap | `lax` ~ `lax`               | string     |

### Routes

| Environment           | Описание                        | Store     | Значение DEV ~ PROD                                      | Тип данных |
|-----------------------|---------------------------------|-----------|----------------------------------------------------------|------------|
| GATEWAY_SERVICE_URL   | URL шлюза                       | ConfigMap | `localhost:9000` / `https://gateway.sorface.com`         | string     |
| INTERVIEW_SERVICE_URL | URL службы сервера для интервью | ConfigMap | `localhost:5043` / `внутренний сервис backend-interview` | string     |
| PASSPORT_SERVICE_URL  | URL службы паспортов            | ConfigMap | `localhost:8080` / `https://api.passport.sorface.com`    | string     |

### OAuth2 (IDP)

| Environment            | Описание                                      | Store | Тип данных |
|------------------------|-----------------------------------------------|-------|------------|
| PASSPORT_CLIENT_ID     | ID клиента службы авторизации IDP             | Vault | string     |
| PASSPORT_CLIENT_SECRET | Секретный ключ клиента службы авторизации IDP | Vault | string     |


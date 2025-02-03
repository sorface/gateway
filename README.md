# Security Gateway

Шлюз безопасности платформы Sorface

## Технологический стек

* Kotlin (2.2.1)
* Spring (3.3.4)
* Spring Security (oauth2-client, oauth2-resource-server)

# Environment

| Environment                | Описание                   |
|----------------------------|-----------------------------|
| CORS_ALLOWED_ORIGINS       | Разрешенные источники       |
| CORS_ALLOWED_METHODS       | Разрешенные методы          |
| CORS_ALLOWED_HEADERS       | Разрешенные заголовки       |
| CORS_ALLOW_CREDENTIALS     | Разрешение использования учетных данных   |
| REDIS_HOST                 | Хост Redis                  |
| REDIS_USERNAME             | Имя пользователя Redis      |
| REDIS_PASSWORD             | Пароль Redis                |
| REDIS_PORT                 | Порт Redis                  |
| GATEWAY_SERVICE_URL        | URL шлюза                   |
| INTERVIEW_SERVICE_URL      | URL службы интервьюирования |
| PASSPORT_SERVICE_URL       | URL службы паспортов        |
| PASSPORT_CLIENT_ID         | ID клиента службы паспортов |
| PASSPORT_CLIENT_SECRET     | Секретный ключ клиента службы паспортов |
| GATEWAY_SESSION_COOKIE_DOMAIN | Домен куки сессии шлюза   |
| GATEWAY_SESSION_COOKIE_NAME | Имя куки сессии шлюза       |
| GATEWAY_SESSION_COOKIE_HTTP_ONLY | Только HTTP для куки сессии шлюза |
| GATEWAY_SESSION_COOKIE_PATH | Путь куки сессии шлюза      |
| GATEWAY_SESSION_COOKIE_SECURE | Безопасность куки сессии шлюза |
| GATEWAY_SESSION_COOKIE_SAME_SITE | Политика одинакового сайта для куки сессии шлюза |

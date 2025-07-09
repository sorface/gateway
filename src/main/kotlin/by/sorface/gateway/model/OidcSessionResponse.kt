package by.sorface.gateway.model

import java.time.Instant

/**
 * Информация о сессиях OIDC пользователя.
 *
 * @property registrationId идентификатор регистрации OAuth2 клиента
 * @property principalName имя пользователя
 * @property sessionId идентификатор сессии
 * @property issuedAt время выдачи сессии
 * @property expiresAt время истечения сессии
 */
data class OidcSessionResponse(
    val registrationId: String,
    val principalName: String,
    val sessionId: String,
    val issuedAt: Instant,
    val expiresAt: Instant
) 
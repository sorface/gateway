package by.sorface.gateway.model

import java.time.Instant

/**
 * Информация о текущей сессии пользователя.
 *
 * @property username имя пользователя
 * @property authorities список ролей/прав пользователя
 * @property authenticated флаг, указывающий на статус аутентификации
 * @property createdAt время создания сессии
 * @property expiresAt время истечения сессии
 */
data class SessionInfo(
    val username: String,
    val authorities: Set<String>,
    val authenticated: Boolean,
    val createdAt: Instant,
    val expiresAt: Instant
) 
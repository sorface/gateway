package by.sorface.gateway.controller

import by.sorface.gateway.model.SessionInfo
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.time.Duration
import java.time.Instant

/**
 * Контроллер для работы с информацией о текущей сессии.
 */
@RestController
@RequestMapping("/api/v1/sessions")
class SessionController {

    /**
     * Получение информации о текущей сессии пользователя.
     * Не включает чувствительные данные, такие как токены.
     *
     * @param authentication текущая аутентификация пользователя
     * @param exchange текущий веб-обмен
     * @return информация о сессии
     */
    @GetMapping
    fun getCurrentSession(
        authentication: Authentication?,
        exchange: ServerWebExchange
    ): Mono<SessionInfo> {
        return exchange.session.map { session ->
            SessionInfo(
                username = authentication?.name ?: "anonymous",
                authorities = authentication?.authorities?.map { it.authority }?.toSet() ?: emptySet(),
                authenticated = authentication?.isAuthenticated ?: false,
                createdAt = session.creationTime,
                expiresAt = session.creationTime.plus(session.maxIdleTime ?: Duration.ofHours(2))
            )
        }
    }
} 
package by.sorface.gateway.controller

import by.sorface.gateway.model.OidcSessionResponse
import by.sorface.gateway.service.RedisReactiveOidcSessionRegistry
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Flux
import java.time.Instant

/**
 * Контроллер для работы с OIDC сессиями.
 */
@RestController
@RequestMapping("/api/v1/oidc/sessions")
class OidcSessionController(
    private val sessionRegistry: RedisReactiveOidcSessionRegistry
) {

    /**
     * Получение списка OIDC сессий для текущего пользователя.
     *
     * @param authentication текущая аутентификация пользователя
     * @param registrationId идентификатор регистрации OAuth2 клиента
     * @return список сессий пользователя
     * @throws ResponseStatusException если пользователь не аутентифицирован
     */
    @GetMapping
    fun getCurrentUserSessions(
        authentication: Authentication?,
        @RequestParam registrationId: String
    ): Flux<OidcSessionResponse> {
        val principalName = authentication?.name
            ?: throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not authenticated")

        return sessionRegistry.findByPrincipalName(principalName, registrationId)
            .map { session ->
                OidcSessionResponse(
                    registrationId = session.registrationId,
                    principalName = session.principalName,
                    sessionId = session.sessionId,
                    issuedAt = session.issuedAt ?: Instant.now(),
                    expiresAt = session.expiresAt ?: Instant.now().plusSeconds(3600)
                )
            }
    }
} 
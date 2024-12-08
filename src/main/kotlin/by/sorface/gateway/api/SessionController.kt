package by.sorface.gateway.api

import org.slf4j.LoggerFactory
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.session.ReactiveFindByIndexNameSessionRepository
import org.springframework.session.Session
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

@RestController
@RequestMapping("/api/gateway/sessions")
class SessionController(private val redisIndexNameSessionRepository: ReactiveFindByIndexNameSessionRepository<out Session>) {

    private val logger = LoggerFactory.getLogger(SessionController::class.java)

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    fun getSession(): Flux<Set<String>> {
        val principal: OidcUser = SecurityContextHolder.getContext().authentication?.principal as OidcUser

        logger.info("Get user session by username ${principal.nickName}")

        return redisIndexNameSessionRepository.findByPrincipalName(principal.nickName).flatMap { session -> Mono.just(session.keys.toSet()) }.flux()
    }

}
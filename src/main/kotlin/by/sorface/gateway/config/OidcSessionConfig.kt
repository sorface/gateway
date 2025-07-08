package by.sorface.gateway.config

import by.sorface.gateway.service.RedisReactiveOidcSessionRegistry
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.web.server.session.WebSessionManager
import reactor.core.publisher.Mono
import org.springframework.web.server.WebSession
import org.springframework.web.server.session.DefaultWebSessionManager
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.web.server.ServerWebExchange

@Configuration
class OidcSessionConfig(
    private val oidcSessionRegistry: RedisReactiveOidcSessionRegistry
) {

    @Bean
    fun webSessionManager(): WebSessionManager {
        return object : DefaultWebSessionManager() {
            override fun getSession(exchange: ServerWebExchange): Mono<WebSession> {
                return super.getSession(exchange)
                    .doOnNext { session ->
                        exchange.getPrincipal()
                            .filter { it is OAuth2AuthenticationToken }
                            .map { it as OAuth2AuthenticationToken }
                            .filter { it.principal is OidcUser }
                            .subscribe { auth ->
                                val oidcUser = auth.principal as OidcUser
                                oidcSessionRegistry.saveSessionInformation(
                                    registrationId = auth.authorizedClientRegistrationId,
                                    principalName = auth.name,
                                    sessionId = session.id,
                                    idToken = oidcUser.idToken
                                ).subscribe()
                            }
                    }
            }
        }
    }

    @Bean
    fun securityContextRepository() = WebSessionServerSecurityContextRepository()

    @Bean
    fun authorizedClientRepository(): ServerOAuth2AuthorizedClientRepository {
        return WebSessionServerOAuth2AuthorizedClientRepository()
    }
} 
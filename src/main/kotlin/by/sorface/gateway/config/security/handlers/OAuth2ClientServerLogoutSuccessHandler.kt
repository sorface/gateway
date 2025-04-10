package by.sorface.gateway.config.security.handlers

import by.sorface.gateway.service.RedisReactiveOAuth2AuthorizedClientService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class OAuth2ClientServerLogoutSuccessHandler(private val redisReactiveOAuth2AuthorizedClientService: RedisReactiveOAuth2AuthorizedClientService) :
    ServerLogoutSuccessHandler {

    private val logger: Logger = LoggerFactory.getLogger(OAuth2ClientServerLogoutSuccessHandler::class.java)

    override fun onLogoutSuccess(exchange: WebFilterExchange?, authentication: Authentication?): Mono<Void> {
        return Mono.defer {
            if (authentication is OAuth2AuthenticationToken) {
                val authorizedClientRegistrationId = authentication.authorizedClientRegistrationId
                val oidcUser = authentication.principal as DefaultOidcUser

                logger.info("logout auth user [client -> ${authorizedClientRegistrationId}, username -> ${oidcUser.name}]")

                return@defer redisReactiveOAuth2AuthorizedClientService.removeAuthorizedClient(authorizedClientRegistrationId, oidcUser.name)
            }

            return@defer Mono.empty()
        }
    }

}
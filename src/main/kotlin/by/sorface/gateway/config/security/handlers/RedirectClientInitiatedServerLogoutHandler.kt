package by.sorface.gateway.config.security.handlers

import by.sorface.gateway.properties.SignOutProperties
import by.sorface.gateway.service.TokenRefreshService
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono
import java.net.URI

@Component
class RedirectClientInitiatedServerLogoutHandler(
    private val reactiveClientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val signOutProperties: SignOutProperties,
    private val tokenRefreshService: TokenRefreshService
) : OidcClientInitiatedServerLogoutSuccessHandler(reactiveClientRegistrationRepository) {

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> {
        val request = exchange.exchange
        val queryParams = request.request.queryParams

        queryParams[signOutProperties.redirectQueryParam]?.firstOrNull()
            ?.let { redirectLocation ->
                super.setPostLogoutRedirectUri(redirectLocation)
                super.setLogoutSuccessUrl(URI(redirectLocation))
            }

        return if (authentication is OAuth2AuthenticationToken) {
            tokenRefreshService
                .refreshTokenAndUpdateAuthenticationIfNeeded(authentication, request)
                .map<Authentication> { oauth2AuthenticationToken -> oauth2AuthenticationToken ?: authentication }
                .defaultIfEmpty(authentication)
                .onErrorReturn(authentication)
                .flatMap { oauth2AuthenticationToken -> super.onLogoutSuccess(exchange, oauth2AuthenticationToken) }
        } else {
            super.onLogoutSuccess(exchange, authentication)
        }
    }
}

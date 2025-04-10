package by.sorface.gateway.config.security.handlers

import by.sorface.gateway.properties.SignOutProperties
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono
import java.net.URI

@Component
class RedirectClientInitiatedServerLogoutHandler(
    private val reactiveClientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val signOutProperties: SignOutProperties
) : OidcClientInitiatedServerLogoutSuccessHandler(reactiveClientRegistrationRepository) {

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> {
        return Mono.just(exchange.exchange)
            .flatMap { webRequest ->
                val queryParams = webRequest.request.queryParams

                if (queryParams.containsKey(signOutProperties.redirectQueryParam)) {
                    val redirectLocation = queryParams.getFirst(signOutProperties.redirectQueryParam)
                    if (redirectLocation != null) {
                        super.setPostLogoutRedirectUri(redirectLocation)
                        super.setLogoutSuccessUrl(URI(redirectLocation))
                    }
                }

                super.onLogoutSuccess(exchange, authentication)
            }
            .then()
    }

}
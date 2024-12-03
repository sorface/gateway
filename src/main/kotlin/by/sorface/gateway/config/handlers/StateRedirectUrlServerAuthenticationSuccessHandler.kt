package by.sorface.gateway.config.handlers

import by.sorface.gateway.config.constants.WebSessionAttributes
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebSession
import reactor.core.publisher.Mono
import java.net.URI
import java.net.URISyntaxException

/**
 * Обработчик успешного входа в систему
 */
class StateRedirectUrlServerAuthenticationSuccessHandler : RedirectServerAuthenticationSuccessHandler() {

    companion object {
        private val DEFAULT_SERVER_REDIRECT_STRATEGY = DefaultServerRedirectStrategy()
    }

    init {
        DEFAULT_SERVER_REDIRECT_STRATEGY.setContextRelative(false)
    }

    /**
     * Обработчик успешной авторизации
     */
    override fun onAuthenticationSuccess(webFilterExchange: WebFilterExchange, authentication: Authentication): Mono<Void> {
        return getRedirectUrl(webFilterExchange.exchange)
            .switchIfEmpty(Mono.defer { super.onAuthenticationSuccess(webFilterExchange, authentication).then(Mono.empty()) })
            .flatMap { redirectUrl: URI? -> DEFAULT_SERVER_REDIRECT_STRATEGY.sendRedirect(webFilterExchange.exchange, redirectUrl) }
    }

    /**
     * Получение из сессии URL для перенаправления
     *
     * @param exchange исходный запрос
     */
    private fun getRedirectUrl(exchange: ServerWebExchange): Mono<URI> {
        return exchange.session
            .filter { webSession: WebSession -> webSession.attributes.containsKey(WebSessionAttributes.ORIGINAL_REQUEST_ATTRIBUTE) }
            .flatMap { webSession: WebSession ->
                val redirectUrl = webSession.attributes[WebSessionAttributes.ORIGINAL_REQUEST_ATTRIBUTE] as String? ?: return@flatMap Mono.empty<URI>()

                webSession.attributes.remove(WebSessionAttributes.ORIGINAL_REQUEST_ATTRIBUTE)

                try {
                    return@flatMap Mono.just<URI>(URI(redirectUrl))
                } catch (e: URISyntaxException) {
                    return@flatMap Mono.error<URI>(e)
                }
            }
            .onErrorResume { Mono.empty() }
    }

}

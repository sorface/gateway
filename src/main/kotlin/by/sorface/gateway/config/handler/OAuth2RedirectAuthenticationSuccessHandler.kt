package by.sorface.gateway.config.handler

import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.ServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI

/**
 * Обработчик успешной OAuth2 аутентификации с поддержкой безопасного редиректа.
 *
 * Обрабатывает перенаправление пользователя после успешной OAuth2 аутентификации:
 * 1. Извлекает URL редиректа из указанного query-параметра в сохраненном запросе
 * 2. Проверяет безопасность URL редиректа (валидация хоста)
 * 3. Выполняет перенаправление на проверенный URL
 *
 * @property requestCache кэш для получения сохраненного запроса
 * @property queryParamNameRedirectLocation имя query-параметра для получения URL редиректа
 * @property allowedHosts список разрешенных хостов для редиректа
 */
class OAuth2RedirectAuthenticationSuccessHandler(
    private val requestCache: ServerRequestCache,
    private val queryParamNameRedirectLocation: String,
    private val allowedHosts: Set<String> = setOf("localhost")
) : ServerAuthenticationSuccessHandler {

    private val logger = LoggerFactory.getLogger(javaClass)
    private val redirectStrategy: ServerRedirectStrategy = DefaultServerRedirectStrategy()

    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange,
        authentication: Authentication
    ): Mono<Void> {
        return requestCache.getRedirectUri(webFilterExchange.exchange)
            .flatMap { uri ->
                // Извлекаем параметр redirect-location из сохраненного URI
                val redirectLocation = UriComponentsBuilder.fromUri(uri)
                    .build()
                    .queryParams
                    .getFirst(queryParamNameRedirectLocation)
                    ?: return@flatMap Mono.error(IllegalStateException("Redirect location is required"))

                // Проверяем и строим URI для редиректа
                Mono.just(redirectLocation)
                    .map { validateAndBuildRedirectUri(it) }
                    .onErrorMap { e -> IllegalArgumentException("Invalid redirect URI: $redirectLocation", e) }
            }
            .flatMap { location ->
                logger.debug("Redirecting after successful authentication to: {}", location)
                redirectStrategy.sendRedirect(webFilterExchange.exchange, location)
            }
    }

    private fun validateAndBuildRedirectUri(redirectLocation: String): URI {
        val uri = UriComponentsBuilder.fromUriString(redirectLocation).build().toUri()
        
        // Проверяем, что URI имеет допустимый хост
        if (uri.host != null && !allowedHosts.contains(uri.host)) {
            logger.warn("Attempted redirect to unauthorized host: {}", uri.host)
            throw IllegalArgumentException("Redirect to unauthorized host: ${uri.host}")
        }
        
        return uri
    }
} 
package by.sorface.gateway.config.repository

import by.sorface.gateway.config.properties.SecurityProperties
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

/**
 * Кастомный репозиторий для сохранения и получения OAuth2 запросов авторизации.
 * Сохраняет оригинальный URL и параметр redirect-location в атрибутах запроса.
 */
@Component
class CustomOAuth2AuthorizationRequestRepository(
    private val securityProperties: SecurityProperties
) : ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    
    private val logger = LoggerFactory.getLogger(CustomOAuth2AuthorizationRequestRepository::class.java)
    private val delegate = WebSessionOAuth2ServerAuthorizationRequestRepository()

    override fun loadAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> {
        return delegate.loadAuthorizationRequest(exchange)
            .doOnNext { request ->
                logger.debug(
                    "Loaded authorization request with attributes - Original URL: {}, Redirect Location: {}",
                    request?.attributes?.get("request-url"),
                    request?.attributes?.get(securityProperties.queryParamNameRedirectLocation)
                )
            }
    }

    override fun removeAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> {
        return delegate.removeAuthorizationRequest(exchange)
            .doOnNext { request ->
                logger.debug(
                    "Removed authorization request with attributes - Original URL: {}, Redirect Location: {}",
                    request?.attributes?.get("request-url"),
                    request?.attributes?.get(securityProperties.queryParamNameRedirectLocation)
                )
            }
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest?,
        exchange: ServerWebExchange
    ): Mono<Void> {
        val enhancedRequest = authorizationRequest?.let { request ->
            val originalUrl = exchange.request.headers.getFirst("Referer") ?: exchange.request.uri.toString()
            val redirectLocation = extractRedirectLocation(originalUrl)

            OAuth2AuthorizationRequest.from(request)
                .attributes { attrs ->
                    attrs.putAll(request.attributes)
                    attrs["request-url"] = originalUrl
                    redirectLocation?.let { attrs[securityProperties.queryParamNameRedirectLocation] = it }
                }
                .build()
        }

        return delegate.saveAuthorizationRequest(enhancedRequest, exchange)
            .doOnSuccess {
                logger.debug(
                    "Saved authorization request with attributes - Original URL: {}, Redirect Location: {}",
                    enhancedRequest?.attributes?.get("request-url"),
                    enhancedRequest?.attributes?.get(securityProperties.queryParamNameRedirectLocation)
                )
            }
    }

    private fun extractRedirectLocation(url: String): String? {
        return try {
            val uri = UriComponentsBuilder.fromUriString(url).build()
            uri.queryParams.getFirst(securityProperties.queryParamNameRedirectLocation)
        } catch (e: Exception) {
            logger.warn("Failed to extract redirect-location from URL: {}", url, e)
            null
        }
    }
} 
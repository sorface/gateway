package by.sorface.gateway.config.resolver

import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

/**
 * Кастомный резолвер запросов авторизации OAuth2.
 * Добавляет исходный URL запроса и параметр redirect-location к атрибутам авторизации.
 */
@Component
class CustomServerOAuth2AuthorizationRequestResolver(
    clientRegistrationRepository: ReactiveClientRegistrationRepository
) : ServerOAuth2AuthorizationRequestResolver {

    private val logger = LoggerFactory.getLogger(CustomServerOAuth2AuthorizationRequestResolver::class.java)
    private val delegate = DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository)

    override fun resolve(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest> {
        return delegate.resolve(exchange)
            .map { request -> addOriginalRequestAttributes(exchange, request) }
            .doOnNext { request -> 
                logger.debug(
                    "Added attributes to authorization request. Original URL: {}, Redirect Location: {}", 
                    request.attributes["request-url"],
                    request.attributes["redirect-location"]
                )
            }
    }

    override fun resolve(exchange: ServerWebExchange, clientRegistrationId: String): Mono<OAuth2AuthorizationRequest> {
        return delegate.resolve(exchange, clientRegistrationId)
            .map { request -> addOriginalRequestAttributes(exchange, request) }
            .doOnNext { request -> 
                logger.debug(
                    "Added attributes to authorization request for client {}. Original URL: {}, Redirect Location: {}", 
                    clientRegistrationId,
                    request.attributes["request-url"],
                    request.attributes["redirect-location"]
                )
            }
    }

    private fun addOriginalRequestAttributes(
        exchange: ServerWebExchange,
        request: OAuth2AuthorizationRequest
    ): OAuth2AuthorizationRequest {
        val originalUrl = exchange.request.headers.getFirst("Referer") ?: exchange.request.uri.toString()
        val redirectLocation = extractRedirectLocation(originalUrl)

        return OAuth2AuthorizationRequest.from(request)
            .attributes { attrs -> 
                attrs.putAll(request.attributes)
                attrs["request-url"] = originalUrl
                redirectLocation?.let { attrs["redirect-location"] = it }
            }
            .build()
    }

    private fun extractRedirectLocation(url: String): String? {
        return try {
            val uri = UriComponentsBuilder.fromUriString(url).build()
            uri.queryParams.getFirst("redirect-location")
        } catch (e: Exception) {
            logger.warn("Failed to extract redirect-location from URL: {}", url, e)
            null
        }
    }
} 
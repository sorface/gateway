package by.sorface.gateway.config.security.resolvers

import by.sorface.gateway.config.security.constants.WebSessionAttributes
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

class SpaServerOAuth2AuthorizationRequestResolver(private val delegate: ServerOAuth2AuthorizationRequestResolver, private val saveParamName: String) :
    ServerOAuth2AuthorizationRequestResolver {

    override fun resolve(exchange: ServerWebExchange?): Mono<OAuth2AuthorizationRequest> {
        return delegate.resolve(exchange)
            .flatMap {
                val originalRequestParam = exchange?.request?.queryParams?.getFirst(saveParamName) ?: return@flatMap Mono.just(it)

                return@flatMap exchange.session.flatMap { session ->
                    session.attributes[WebSessionAttributes.ORIGINAL_REQUEST_ATTRIBUTE] = originalRequestParam

                    Mono.just(it)
                }
            }
    }

    override fun resolve(exchange: ServerWebExchange?, clientRegistrationId: String?): Mono<OAuth2AuthorizationRequest> {
        return delegate.resolve(exchange, clientRegistrationId)
    }

}
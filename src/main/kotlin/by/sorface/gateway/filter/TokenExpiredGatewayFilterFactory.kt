package by.sorface.gateway.filter

import by.sorface.gateway.extension.toJson
import by.sorface.gateway.records.ErrorResponse
import io.micrometer.tracing.Tracer
import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.cloud.gateway.route.Route
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.OAuth2AuthorizationException
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

/**
 * Фильтр для обработки истекших токенов (access и refresh).
 * Предотвращает 302 редирект на IDP сервер, вместо этого возвращает 401.
 */
@Component("TokenExpired")
class TokenExpiredGatewayFilterFactory(
    private val authorizedClientService: ReactiveOAuth2AuthorizedClientService,
    private val tracer: Tracer
) : AbstractGatewayFilterFactory<TokenExpiredGatewayFilterFactory.Config>(Config::class.java) {

    private val log = LoggerFactory.getLogger(this::class.java)

    override fun apply(config: Config): GatewayFilter = GatewayFilter { exchange, chain ->
        val route = exchange.getAttribute<Route>(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR)

        ReactiveSecurityContextHolder.getContext()
            .map { it.authentication }
            .cast(OAuth2AuthenticationToken::class.java)
            .map { it to true }
            .defaultIfEmpty(null to false)
            .flatMap { (token, hasAuthentication) ->
                if (!hasAuthentication) {
                    chain.filter(exchange)
                } else {
                    chain.filter(exchange)
                        .onErrorResume(OAuth2AuthorizationException::class.java) { ex ->
                            log.debug(
                                "Token expired for route [id: {}, uri: {}]: {}",
                                route?.id,
                                route?.uri,
                                ex.message
                            )

                            exchange.session
                                .flatMap { session ->
                                    val sessionId = session.id

                                    log.debug("deleting session [id -> {}]", sessionId)

                                    session.invalidate().then()
                                }
                                .onErrorResume { Mono.empty() }
                                .then(Mono.defer {
                                    log.debug(
                                        "deleting authorized client [id -> {}, name -> {}]",
                                        token.authorizedClientRegistrationId, token.name
                                    )

                                    authorizedClientService.removeAuthorizedClient(token.authorizedClientRegistrationId, token.name)
                                })
                                .then(Mono.defer {
                                    val currentSpan = tracer.currentSpan()

                                    exchange.response.toJson(
                                        HttpStatus.UNAUTHORIZED, ErrorResponse(
                                            traceId = currentSpan?.context()?.traceId() ?: "unknown",
                                            spanId = currentSpan?.context()?.spanId() ?: "unknown",
                                            code = HttpStatus.UNAUTHORIZED.value(),
                                            reason = "Token expired or invalid"
                                        )
                                    )
                                })
                        }
                }
            }
    }

    class Config
}
package by.sorface.gateway.config.route

import io.micrometer.tracing.Tracer
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ORIGINAL_REQUEST_URL_ATTR
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.URI
import java.security.Principal

@Configuration
class RouteFilterConfiguration {

    private val logger = LoggerFactory.getLogger(javaClass)

    @Autowired
    private lateinit var tracer: Tracer

    @Bean
    fun preRouteFilter(): GlobalFilter {
        return GlobalFilter { exchange: ServerWebExchange, chain: GatewayFilterChain ->
            exchange.getPrincipal<Principal>()
                .map<Any> {
                    if (it is OAuth2AuthenticationToken) {
                        val id = it.principal.attributes["name"] as String?

                        if (id.isNullOrEmpty().not()) {
                            return@map id!!
                        }
                    }

                    it.name
                }
                .defaultIfEmpty("anonymous")
                .map {
                    val traceId = tracer.currentTraceContext().context()?.traceId()

                    if (traceId.isNullOrEmpty().not()) {
                        exchange.response.headers.add("X-B3-TraceId", traceId)
                    }

                    val originalRequestAttr = exchange.getAttributeOrDefault<Set<URI>>(GATEWAY_ORIGINAL_REQUEST_URL_ATTR, setOf())

                    val secureRequest = exchange.request.headers.containsKey(HttpHeaders.AUTHORIZATION)

                    logger.info("request: [user -> $it, gateway request -> ${originalRequestAttr.firstOrNull()}, " +
                            "target request -> ${exchange.request.uri}, secure -> ${secureRequest}], token -> ${exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)}")

                    exchange
                }
                .flatMap { chain.filter(exchange) }
        }
    }

    @Bean
    fun postRouteFilter(): GlobalFilter {
        return GlobalFilter { exchange: ServerWebExchange, chain: GatewayFilterChain ->
            chain.filter(exchange)
                .then(Mono.just(exchange))
                .flatMap { exchange.getPrincipal<Principal>() }
                .map {
                    if (it is OAuth2AuthenticationToken) {
                        val id = it.principal.attributes["name"] as String?

                        if (id.isNullOrEmpty().not()) {
                            return@map id!!
                        }
                    }
                    it.name
                }
                .defaultIfEmpty("anonymous")
                .map {
                    val serverHttpResponse = exchange.response
                    val serverHttpRequest = exchange.request

                    logger.info("response: [user -> $it, uri -> ${serverHttpRequest.uri}, status -> ${serverHttpResponse.statusCode}]")

                    exchange
                }

                .then()
        }
    }
}
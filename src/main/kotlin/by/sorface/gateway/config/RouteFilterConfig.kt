package by.sorface.gateway.config

import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import org.springframework.security.core.Authentication

@Configuration
class RouteFilterConfig {
    private val log = LoggerFactory.getLogger(RouteFilterConfig::class.java)

    @Bean
    fun preRouteFilter(): GlobalFilter {
        return OrderedGlobalFilter(Int.MIN_VALUE) { exchange, chain ->
            ReactiveSecurityContextHolder.getContext()
                .map { it.authentication!! }
                .flatMap { auth ->
                    val request = exchange.request
                    log.info(
                        "Proxy Request - User: {}, Method: {}, Path: {}, Headers: {}, Query: {}",
                        auth?.name ?: "anonymous",
                        request.method,
                        request.uri.path,
                        formatHeaders(request),
                        request.queryParams
                    )
                    chain.filter(exchange)
                }
        }
    }

    @Bean
    fun postRouteFilter(): GlobalFilter {
        return OrderedGlobalFilter(Int.MAX_VALUE) { exchange, chain ->
            chain.filter(exchange).then(Mono.fromRunnable {
                ReactiveSecurityContextHolder.getContext()
                    .map { it.authentication!! }
                    .subscribe { auth ->
                        val response = exchange.response
                        log.info(
                            "Proxy Response - User: {}, Status: {}, Headers: {}",
                            auth?.name ?: "anonymous",
                            response.statusCode,
                            response.headers
                        )
                    }
            })
        }
    }

    private fun formatHeaders(request: ServerHttpRequest): Map<String, String> {
        return request.headers.entries
            .filter { (key, _) -> !SENSITIVE_HEADERS.contains(key.lowercase()) }
            .associate { (key, value) -> key to value.joinToString(", ") }
    }

    companion object {
        private val SENSITIVE_HEADERS = setOf(
            "authorization",
            "cookie",
            "set-cookie",
            "x-xsrf-token"
        )
    }
}

private class OrderedGlobalFilter(
    private val order: Int,
    private val filter: (ServerWebExchange, GatewayFilterChain) -> Mono<Void>
) : GlobalFilter, Ordered {
    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        return filter(exchange, chain)
    }

    override fun getOrder(): Int = order
} 
package by.sorface.gateway.filter

import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.cloud.gateway.route.Route
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

/**
 * Фильтр для краткого логирования запросов и ответов.
 */
@Component
class LoggingGatewayFilterFactory : AbstractGatewayFilterFactory<LoggingGatewayFilterFactory.Config>(Config::class.java) {

    private val log = LoggerFactory.getLogger(this::class.java)

    override fun apply(config: Config): GatewayFilter = GatewayFilter { exchange, chain ->
        val request = exchange.request
        val startTime = System.currentTimeMillis()
        val method = request.method
        val originalUri = request.uri.path

        val route = exchange.getAttribute<Route>(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR)

        log.info("[REQ] [route id -> {}, method -> {}, route -> {}{}]", route?.id, method, route?.uri, originalUri)

        chain.filter(exchange)
            .then(Mono.fromRunnable {
                val endTime = System.currentTimeMillis()
                val status = exchange.response.statusCode

                log.info("[RES] [route id -> {}, method -> {}, path -> {}{}] [http status -> {}, time (ms) -> {}]",
                    route?.id, method, route?.uri, originalUri, status, endTime - startTime)
            })
    }

    class Config
}
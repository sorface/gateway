package by.sorface.gateway.filter

import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.cloud.gateway.route.Route
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ResponseStatusException
import reactor.core.publisher.Mono

/**
 * Фильтр для обработки ошибок от внешних сервисов.
 * Логирует ошибки и преобразует их в стандартный формат.
 */
@Component
class ErrorHandlingGatewayFilterFactory : AbstractGatewayFilterFactory<ErrorHandlingGatewayFilterFactory.Config>(Config::class.java) {

    private val log = LoggerFactory.getLogger(this::class.java)

    override fun apply(config: Config): GatewayFilter = GatewayFilter { exchange, chain ->
        chain.filter(exchange)
            .onErrorResume { error ->
                val originalStatus = when (error) {
                    is ResponseStatusException -> error.statusCode
                    else -> HttpStatus.INTERNAL_SERVER_ERROR
                }

                val route = exchange.getAttribute<Route>(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR)

                log.error("[error] [route id -> {}, uri -> {}{}, status -> {}] {}", route?.id, route?.uri, exchange.request.path, originalStatus, error.message)

                val response = exchange.response
                response.statusCode = originalStatus

                Mono.empty()
            }
    }

    class Config
}
package by.sorface.gateway.config.tracing

import org.slf4j.MDC
import org.springframework.core.Ordered
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import java.util.*

@Component
class ContextPropagationWebFilter : WebFilter, Ordered {

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        val traceId = exchange.request.headers["X-Trace-Id"]?.firstOrNull() ?: UUID.randomUUID().toString()
        
        return Mono.deferContextual { context ->
            MDC.put("traceId", traceId)
            exchange.response.headers.add("X-Trace-Id", traceId)
            
            chain.filter(exchange)
                .doFinally { MDC.clear() }
        }
    }

    override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE
}
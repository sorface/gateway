package by.sorface.gateway.config

import io.micrometer.context.ContextRegistry
import io.micrometer.tracing.Tracer
import io.micrometer.tracing.handler.DefaultTracingObservationHandler
import io.micrometer.tracing.handler.PropagatingReceiverTracingObservationHandler
import io.micrometer.tracing.handler.PropagatingSenderTracingObservationHandler
import io.micrometer.tracing.propagation.Propagator
import jakarta.annotation.PostConstruct
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import reactor.core.publisher.Hooks

@Configuration
class TracingConfig {

    @PostConstruct
    fun init() {
        Hooks.enableAutomaticContextPropagation()

        // Регистрируем обработчик для MDC
        ContextRegistry.getInstance()
            .registerThreadLocalAccessor(
                "MDC",
                { org.slf4j.MDC.getCopyOfContextMap() ?: emptyMap() },
                { context -> org.slf4j.MDC.setContextMap(context) },
                { org.slf4j.MDC.clear() }
            )
    }

    @Bean
    fun tracingObservationHandler(tracer: Tracer, propagator: Propagator): DefaultTracingObservationHandler {
        return DefaultTracingObservationHandler(tracer)
    }

    @Bean
    fun propagatingReceiverTracingObservationHandler(tracer: Tracer, propagator: Propagator): PropagatingReceiverTracingObservationHandler<Nothing> {
        return PropagatingReceiverTracingObservationHandler(tracer, propagator)
    }

    @Bean
    fun propagatingSenderTracingObservationHandler(tracer: Tracer, propagator: Propagator): PropagatingSenderTracingObservationHandler<Nothing> {
        return PropagatingSenderTracingObservationHandler(tracer, propagator)
    }
} 
package by.sorface.gateway.config

import io.micrometer.context.ContextRegistry
import io.micrometer.observation.ObservationRegistry
import io.micrometer.tracing.Tracer
import io.micrometer.tracing.handler.DefaultTracingObservationHandler
import io.micrometer.tracing.handler.PropagatingReceiverTracingObservationHandler
import io.micrometer.tracing.handler.PropagatingSenderTracingObservationHandler
import io.micrometer.tracing.propagation.Propagator
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import reactor.core.publisher.Hooks
import jakarta.annotation.PostConstruct

@Configuration
class TracingConfig {

    @PostConstruct
    fun init() {
        Hooks.enableAutomaticContextPropagation()
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
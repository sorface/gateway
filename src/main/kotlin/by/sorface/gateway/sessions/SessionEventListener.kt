package by.sorface.gateway.sessions

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.context.event.EventListener
import org.springframework.session.events.SessionCreatedEvent
import org.springframework.session.events.SessionDeletedEvent
import org.springframework.session.events.SessionExpiredEvent
import org.springframework.stereotype.Component
import reactor.core.publisher.Mono

@Component
class SessionEventListener {

    private val logger: Logger = LoggerFactory.getLogger(SessionEventListener::class.java)

    @EventListener
    fun processSessionCreatedEvent(event: SessionCreatedEvent): Mono<Void> {
        logger.info("Session created: {}", event.sessionId)

        return Mono.empty()
    }

    @EventListener
    fun processSessionDeletedEvent(event: SessionDeletedEvent): Mono<Void> {
        logger.info("Session deleted: {}", event.sessionId)

        return Mono.empty()
    }

    @EventListener
    fun processSessionExpiredEvent(event: SessionExpiredEvent): Mono<Void> {
        logger.info("Session expired: {}", event.sessionId)

        return Mono.empty()
    }
}

package by.sorface.gateway.config.security.handlers

import by.sorface.gateway.utils.JsonHttpResponseUtils
import org.slf4j.LoggerFactory
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.client.ClientAuthorizationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.net.ConnectException
import java.net.URI

/**
 * Глобальный обработчик исключений
 */
class GlobalErrorWebExceptionHandler : ErrorWebExceptionHandler {

    private val logger = LoggerFactory.getLogger(javaClass)

    /**
     * Обработка глобального исключения
     *
     * @param exchange запрос, при котором было выброшено исключение
     * @param throwable выброшенное исключение
     */
    override fun handle(exchange: ServerWebExchange, throwable: Throwable): Mono<Void> {
        return Mono.defer {
            val response = exchange.response

            if (throwable is ClientAuthorizationException) {
                val error: OAuth2Error = throwable.error

                return@defer when (error.errorCode) {
                    OAuth2ErrorCodes.INVALID_GRANT -> {
                        logger.info("Token expired. redirect to origin page. Message {}", throwable.message)

                        exchange.response.cookies.clear()
                        exchange.response.headers.location = exchange.request.headers.origin?.let { URI.create(it) }

                        JsonHttpResponseUtils.buildJsonResponseWithException(response, HttpStatus.UNAUTHORIZED, "the session expired")
                    }
                    OAuth2ErrorCodes.ACCESS_DENIED -> JsonHttpResponseUtils.buildJsonResponseWithException(response, HttpStatus.FORBIDDEN, "access denied")

                    else -> {
                        logger.error("ClientAuthorizationException error occurred", throwable)

                        JsonHttpResponseUtils.buildJsonResponseWithException(response, throwable = throwable)
                    }
                }
            }

            if (throwable.cause is ConnectException) {
                logger.error("service unavailable. Message {}", throwable.message)

                return@defer JsonHttpResponseUtils.buildJsonResponseWithException(response, HttpStatus.SERVICE_UNAVAILABLE, throwable = throwable)
            }

            logger.error("unknown error occurred", throwable)

            JsonHttpResponseUtils.buildJsonResponseWithException(response, throwable = throwable)
        }
    }

}

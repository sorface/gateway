package by.sorface.gateway.config.handlers

import by.sorface.gateway.utils.JsonHttpResponseUtils
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.client.ClientAuthorizationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Глобальный обработчик исключений
 */
class GlobalErrorWebExceptionHandler : ErrorWebExceptionHandler {

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
                    OAuth2ErrorCodes.INVALID_GRANT -> JsonHttpResponseUtils.buildJsonResponseWithException(response, HttpStatus.UNAUTHORIZED, "The session expired")
                    OAuth2ErrorCodes.ACCESS_DENIED -> JsonHttpResponseUtils.buildJsonResponseWithException(response, HttpStatus.FORBIDDEN, "Access denied")
                    else -> JsonHttpResponseUtils.buildJsonResponseWithException(response, throwable = throwable)
                }
            }

            JsonHttpResponseUtils.buildJsonResponseWithException(response, throwable = throwable)
        }
    }

}

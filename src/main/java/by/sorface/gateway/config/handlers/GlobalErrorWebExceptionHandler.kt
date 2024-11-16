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
 * This is a custom ErrorWebExceptionHandler that handles exceptions that occur during the execution of the application.
 *
 * @author Sorface
 */
class GlobalErrorWebExceptionHandler : ErrorWebExceptionHandler {
    /**
     * This method handles exceptions by converting them to JSON responses.
     * If the exception is an instance of ClientAuthorizationException, it checks the error code and responds with an appropriate HTTP status code.
     * If the error code is INVALID_GRANT, it responds with a 401 UNAUTHORIZED status code and a message indicating that the session expired.
     * For all other errors, it responds with a 500 INTERNAL_SERVER_ERROR status code.
     *
     * @param exchange  the ServerWebExchange object
     * @param throwable the Throwable object
     * @return the Mono<Void> object
    </Void> */
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

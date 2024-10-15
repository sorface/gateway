package by.sorface.gateway.config.handlers;

import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static by.sorface.gateway.utils.JsonHttpResponseUtils.buildJsonResponseWithException;

/**
 * This is a custom ErrorWebExceptionHandler that handles exceptions that occur during the execution of the application.
 *
 * @author Sorface
 */
public class GlobalErrorWebExceptionHandler implements ErrorWebExceptionHandler {

    /**
     * This method handles exceptions by converting them to JSON responses.
     * If the exception is an instance of ClientAuthorizationException, it checks the error code and responds with an appropriate HTTP status code.
     * If the error code is INVALID_GRANT, it responds with a 401 UNAUTHORIZED status code and a message indicating that the session expired.
     * For all other errors, it responds with a 500 INTERNAL_SERVER_ERROR status code.
     *
     * @param exchange  the ServerWebExchange object
     * @param throwable the Throwable object
     * @return the Mono<Void> object
     */
    @SuppressWarnings("NullableProblems")
    @Override
    public Mono<Void> handle(final ServerWebExchange exchange, final Throwable throwable) {
        return Mono.defer(() -> {
            final ServerHttpResponse response = exchange.getResponse();

            if (throwable instanceof ClientAuthorizationException clientAuthorizationException) {
                final OAuth2Error error = clientAuthorizationException.getError();

                return switch (error.getErrorCode()) {
                    case OAuth2ErrorCodes.INVALID_GRANT -> buildJsonResponseWithException(response, HttpStatus.UNAUTHORIZED, "The session expired");
                    case OAuth2ErrorCodes.ACCESS_DENIED -> buildJsonResponseWithException(response, HttpStatus.FORBIDDEN, "Access denied");
                    default -> buildJsonResponseWithException(response, HttpStatus.INTERNAL_SERVER_ERROR, throwable);
                };
            }

            return buildJsonResponseWithException(response, HttpStatus.INTERNAL_SERVER_ERROR, throwable);
        });
    }

}

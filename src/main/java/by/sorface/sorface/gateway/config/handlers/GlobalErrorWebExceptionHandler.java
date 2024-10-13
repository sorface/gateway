package by.sorface.sorface.gateway.config.handlers;

import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static by.sorface.sorface.gateway.utils.JsonHttpResponseUtils.toJsonException;

public class GlobalErrorWebExceptionHandler implements ErrorWebExceptionHandler {

    @SuppressWarnings("NullableProblems")
    @Override
    public Mono<Void> handle(final ServerWebExchange exchange, final Throwable throwable) {
        if (throwable instanceof ClientAuthorizationException clientAuthorizationException) {
            final OAuth2Error error = clientAuthorizationException.getError();

            return switch (error.getErrorCode()) {
                case OAuth2ErrorCodes.INVALID_GRANT -> toJsonException(exchange.getResponse(), HttpStatus.UNAUTHORIZED, "The session expired");
                default -> toJsonException(exchange.getResponse(), HttpStatus.INTERNAL_SERVER_ERROR, throwable);
            };
        }

        return toJsonException(exchange.getResponse(), HttpStatus.INTERNAL_SERVER_ERROR, throwable);
    }

}

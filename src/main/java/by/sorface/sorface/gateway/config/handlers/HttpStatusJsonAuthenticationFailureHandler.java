package by.sorface.sorface.gateway.config.handlers;

import by.sorface.sorface.gateway.utils.JsonHttpResponseUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import reactor.core.publisher.Mono;

public class HttpStatusJsonAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {

    private final HttpStatus httpStatus;

    public HttpStatusJsonAuthenticationFailureHandler(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
        return Mono.defer(() -> Mono.just(webFilterExchange.getExchange().getResponse())).flatMap((response) -> {
            response.setStatusCode(this.httpStatus);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

            return JsonHttpResponseUtils.toJsonException(response, httpStatus, exception);
        });
    }

}

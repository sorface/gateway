package by.sorface.gateway.config.handlers;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static by.sorface.gateway.utils.JsonHttpResponseUtils.buildJsonResponseWithException;

public class HttpStatusJsonServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final HttpStatus httpStatus;

    public HttpStatusJsonServerAuthenticationEntryPoint(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
        Assert.notNull(httpStatus, "httpStatus cannot be null");
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        return Mono.just(exchange.getResponse()).flatMap(response -> {
            response.setStatusCode(httpStatus);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

            return buildJsonResponseWithException(response, httpStatus, ex);
        });
    }

}

package by.sorface.sorface.gateway.config.handlers;

import by.sorface.sorface.gateway.JsonHttpResponseUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class HttpStatusJsonServerAccessDeniedHandler implements ServerAccessDeniedHandler {

    private final HttpStatus httpStatus;

    public HttpStatusJsonServerAccessDeniedHandler(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
        Assert.notNull(httpStatus, "httpStatus cannot be null");
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        return Mono.defer(() -> Mono.just(exchange.getResponse())).flatMap((response) -> {
            response.setStatusCode(this.httpStatus);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

            return JsonHttpResponseUtils.toJsonException(response, httpStatus, denied);
        });
    }

}

package by.sorface.gateway.config.entrypoints

import by.sorface.gateway.utils.JsonHttpResponseUtils
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.util.Assert
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

class HttpStatusJsonServerAuthenticationEntryPoint(
    private val httpStatus: HttpStatus
) : ServerAuthenticationEntryPoint {

    init {
        Assert.notNull(httpStatus, "HTTP Status cannot be null")
    }

    override fun commence(exchange: ServerWebExchange, ex: AuthenticationException): Mono<Void> {
        return Mono.just(exchange.response)
            .flatMap { response ->
                response.setStatusCode(httpStatus)
                response.headers.contentType = MediaType.APPLICATION_JSON
                return@flatMap JsonHttpResponseUtils.buildJsonAuthorizationError(response, httpStatus, ex)
            }
    }
}

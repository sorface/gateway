package by.sorface.gateway.config.security.handlers

import by.sorface.gateway.utils.JsonHttpResponseUtils
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import reactor.core.publisher.Mono

/**
 * Обработчик исключение при неавторизованном доступе к ресурсам
 */
class HttpStatusJsonAuthenticationFailureHandler(private val httpStatus: HttpStatus) : ServerAuthenticationFailureHandler {

    /**
     * Обработка запроса, при выполнении которого было выброшено исключение об отсутствии аутентификации
     *
     * @param webFilterExchange фильтр, на котором было выброшено исключение
     */
    override fun onAuthenticationFailure(webFilterExchange: WebFilterExchange, exception: AuthenticationException): Mono<Void> {
        return Mono.defer { Mono.just(webFilterExchange.exchange.response) }
            .flatMap { response: ServerHttpResponse ->
                response.setStatusCode(this.httpStatus)
                response.headers.contentType = MediaType.APPLICATION_JSON
                JsonHttpResponseUtils.buildJsonResponseWithException(response, httpStatus, exception)
            }
    }

}

package by.sorface.gateway.config.handlers

import by.sorface.gateway.utils.JsonHttpResponseUtils
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler
import org.springframework.util.Assert
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Обработчик исключение при доступе к ресурсам для которого нет разрешения
 */
class HttpStatusJsonServerAccessDeniedHandler(private val httpStatus: HttpStatus) : ServerAccessDeniedHandler {

    init {
        Assert.notNull(httpStatus, "httpStatus cannot be null")
    }

    /**
     * Обработка запроса при котором было выброшено исключение
     * @param exchange пользовательский запрос
     * @param denied исключение при отсутствии разрешений на доступ к ресурсу
     */
    override fun handle(exchange: ServerWebExchange, denied: AccessDeniedException): Mono<Void> {
        return Mono.defer { Mono.just(exchange.response) }
            .flatMap { response: ServerHttpResponse ->
                response.setStatusCode(this.httpStatus)
                response.headers.contentType = MediaType.APPLICATION_JSON
                JsonHttpResponseUtils.buildJsonResponseWithException(response, httpStatus, denied)
            }
    }
}

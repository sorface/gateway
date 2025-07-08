package by.sorface.gateway.config

import by.sorface.gateway.model.ErrorResponse
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.core.io.buffer.DataBufferFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.core.AuthenticationException
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Configuration
class SecurityErrorConfig(private val objectMapper: ObjectMapper) {

    @Bean
    @Order(-2)
    fun errorWebExceptionHandler(): ErrorWebExceptionHandler {
        return ErrorWebExceptionHandler { exchange: ServerWebExchange, ex: Throwable ->
            when (ex) {
                is AuthenticationException -> handleAuthenticationError(exchange, ex)
                is AccessDeniedException -> handleAccessDeniedError(exchange, ex)
                else -> Mono.error(ex)
            }
        }
    }

    private fun handleAuthenticationError(exchange: ServerWebExchange, ex: AuthenticationException): Mono<Void> {
        val response = exchange.response
        response.statusCode = HttpStatus.UNAUTHORIZED
        response.headers.contentType = MediaType.APPLICATION_JSON

        val errorResponse = ErrorResponse(
            message = ex.message ?: "Authentication failed",
            code = HttpStatus.UNAUTHORIZED.value().toString()
        )

        val bufferFactory: DataBufferFactory = response.bufferFactory()
        val buffer = bufferFactory.wrap(objectMapper.writeValueAsBytes(errorResponse))

        return response.writeWith(Mono.just(buffer))
    }

    private fun handleAccessDeniedError(exchange: ServerWebExchange, ex: AccessDeniedException): Mono<Void> {
        val response = exchange.response
        response.statusCode = HttpStatus.FORBIDDEN
        response.headers.contentType = MediaType.APPLICATION_JSON

        val errorResponse = ErrorResponse(
            message = ex.message ?: "Access denied",
            code = HttpStatus.FORBIDDEN.value().toString()
        )

        val bufferFactory: DataBufferFactory = response.bufferFactory()
        val buffer = bufferFactory.wrap(objectMapper.writeValueAsBytes(errorResponse))

        return response.writeWith(Mono.just(buffer))
    }
} 
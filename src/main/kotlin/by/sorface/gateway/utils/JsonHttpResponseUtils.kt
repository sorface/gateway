package by.sorface.gateway.utils

import by.sorface.gateway.records.ErrorOperation
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpResponse
import reactor.core.publisher.Mono

object JsonHttpResponseUtils {

    private val OBJECT_MAPPER = ObjectMapper()

    fun buildJsonResponseWithException(response: ServerHttpResponse, httpStatus: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR, throwable: Throwable): Mono<Void> {
        return buildJsonResponseWithException(response, httpStatus, throwable.message)
    }

    fun buildJsonResponseWithException(response: ServerHttpResponse, httpStatus: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR, message: String? = null): Mono<Void> {
        return buildJsonResponseWithException(response, httpStatus, ErrorOperation(httpStatus.value(), message))
    }

    private fun buildJsonResponseWithException(response: ServerHttpResponse, httpStatus: HttpStatus, jsonObject: Any): Mono<Void> {
        val dataBufferFactory = response.bufferFactory()

        response.setStatusCode(httpStatus)

        val dataBufferMono = Mono.defer {
            var result: Mono<ByteArray>

            try {
                val data = OBJECT_MAPPER.writeValueAsBytes(jsonObject)

                result = Mono.just(data)
            } catch (e: JsonProcessingException) {
                result = Mono.error(e)
            }

            result
        }
            .map { bytes: ByteArray -> dataBufferFactory.wrap(bytes) }

        return response.writeWith(dataBufferMono)
    }
}

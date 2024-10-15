package by.sorface.gateway.utils;

import by.sorface.gateway.records.ErrorOperation;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

public final class JsonHttpResponseUtils {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static Mono<Void> buildJsonResponseWithException(final ServerHttpResponse response, final HttpStatus httpStatus, final Throwable throwable) {
        return buildJsonResponseWithException(response, httpStatus, throwable.getMessage());
    }

    public static Mono<Void> buildJsonResponseWithException(final ServerHttpResponse response, final HttpStatus httpStatus, final String message) {
        final DataBufferFactory dataBufferFactory = response.bufferFactory();

        response.setStatusCode(httpStatus);

        Mono<DataBuffer> dataBufferMono = Mono.defer(() -> {
                    Mono<byte[]> result;

                    try {
                        byte[] data = OBJECT_MAPPER.writeValueAsBytes(new ErrorOperation(httpStatus.value(), message));

                        result = Mono.just(data);
                    } catch (JsonProcessingException e) {
                        result = Mono.error(e);
                    }

                    return result;
                })
                .map(dataBufferFactory::wrap);

        return response.writeWith(dataBufferMono);
    }

}

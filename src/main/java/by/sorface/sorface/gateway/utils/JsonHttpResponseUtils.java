package by.sorface.sorface.gateway.utils;

import by.sorface.sorface.gateway.records.ErrorOperation;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

import java.util.Map;

public final class JsonHttpResponseUtils {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static Mono<Void> toJsonException(final ServerHttpResponse response, final HttpStatus httpStatus, final Throwable throwable) {
        return toJsonException(response, httpStatus, throwable.getMessage());
    }

    public static Mono<Void> toJsonException(final ServerHttpResponse response, final HttpStatus httpStatus, final String message) {
        final DataBufferFactory dataBufferFactory = response.bufferFactory();

        DataBuffer buffer;

        try {
            buffer = dataBufferFactory.wrap(OBJECT_MAPPER.writeValueAsBytes(new ErrorOperation(httpStatus.value(), message)));
        } catch (JsonProcessingException e) {
            return Mono.error(e);
        }

        return response.writeWith(Mono.just(buffer)).doOnError((error) -> DataBufferUtils.release(buffer));
    }

}

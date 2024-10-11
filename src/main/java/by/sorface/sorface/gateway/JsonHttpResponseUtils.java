package by.sorface.sorface.gateway;

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

    public static Mono<Void> toJsonException(final ServerHttpResponse response, final HttpStatus httpStatus, final Throwable throwable) {
        final DataBufferFactory dataBufferFactory = response.bufferFactory();

        DataBuffer buffer;
        try {
            buffer = dataBufferFactory.wrap(
                    new ObjectMapper().writeValueAsBytes(Map.of(
                            "code", httpStatus.value(),
                            "message", throwable.getMessage()
                    ))
            );
        } catch (JsonProcessingException e) {
            return Mono.error(e);
        }

        return response
                .writeWith(Mono.just(buffer))
                .doOnError((error) -> DataBufferUtils.release(buffer));
    }

}

package by.sorface.gateway.extension

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.HttpStatus
import org.springframework.http.server.reactive.ServerHttpResponse
import reactor.core.publisher.Mono
import java.io.*

@Suppress("UNCHECKED_CAST")
fun <T : Serializable> fromByteArray(byteArray: ByteArray): T {
    val byteArrayInputStream = ByteArrayInputStream(byteArray)
    val objectInput: ObjectInput = ObjectInputStream(byteArrayInputStream)
    val result = objectInput.readObject() as T
    objectInput.close()
    byteArrayInputStream.close()
    return result
}

fun Serializable.toByteArray(): ByteArray {
    val byteArrayOutputStream = ByteArrayOutputStream()
    val objectOutputStream = ObjectOutputStream(byteArrayOutputStream)
    objectOutputStream.writeObject(this)
    objectOutputStream.flush()
    val result = byteArrayOutputStream.toByteArray()
    byteArrayOutputStream.close()
    objectOutputStream.close()
    return result
}

private val OBJECT_MAPPER = ObjectMapper()

fun ServerHttpResponse.toJson(httpStatus: HttpStatus, jsonObject: Any): Mono<Void> {
    val dataBufferFactory = this.bufferFactory()

    this.statusCode = httpStatus

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

    return this.writeWith(dataBufferMono)
}
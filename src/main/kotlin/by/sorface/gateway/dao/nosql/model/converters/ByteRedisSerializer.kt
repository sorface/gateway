package by.sorface.gateway.dao.nosql.model.converters

import by.sorface.gateway.extension.fromByteArray
import by.sorface.gateway.extension.toByteArray
import org.springframework.data.redis.serializer.RedisSerializer
import java.io.Serializable

open class ByteRedisSerializer<T : Serializable> : RedisSerializer<T> {

    override fun serialize(value: T?): ByteArray {
        if (value == null) {
            return ByteArray(0)
        }

        return convert(value)
    }

    override fun deserialize(bytes: ByteArray?): T? {
        if (bytes == null || bytes.isEmpty()) {
            return null
        }

        return convert(bytes)
    }

    private fun convert(source: ByteArray): T = fromByteArray(source)

    private fun convert(source: T): ByteArray = source.toByteArray()

}
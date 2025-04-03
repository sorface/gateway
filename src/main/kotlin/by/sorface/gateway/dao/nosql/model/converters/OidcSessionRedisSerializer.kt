package by.sorface.gateway.dao.nosql.model.converters

import by.sorface.gateway.config.fromByteArray
import by.sorface.gateway.config.toByteArray
import org.springframework.data.convert.ReadingConverter
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.stereotype.Component
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

/**
 * Конвертер, преобразующий массив байтов в объект [OidcSessionInformation].
 */
@Component
@ReadingConverter
class OidcSessionRedisSerializer : RedisSerializer<OidcSessionInformation> {

    /**
     * Преобразует массив байтов в объект [OidcSessionInformation].
     *
     * @param source Массив байтов, который нужно преобразовать.
     * @return Объект [OidcSessionInformation].
     * @throws RuntimeException Если возникает исключение при чтении объекта.
     */
    fun convert(source: ByteArray): OidcSessionInformation {
        return fromByteArray(source)
    }

    fun convert(source: OidcSessionInformation): ByteArray {
        return source.toByteArray()
    }
    override fun serialize(value: OidcSessionInformation?): ByteArray {
        if (value == null) {
            return ByteArray(0)
        }

        return convert(value)
    }

    override fun deserialize(bytes: ByteArray?): OidcSessionInformation? {
        if (bytes == null || bytes.isEmpty()) {
            return null
        }

        return convert(bytes)
    }

}

package by.sorface.gateway.config.serializer

import by.sorface.gateway.model.OidcSessionInformation
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.springframework.data.redis.serializer.RedisSerializer

class OidcSessionInformationRedisSerializer : RedisSerializer<OidcSessionInformation> {
    private val objectMapper: ObjectMapper = ObjectMapper()
        .registerKotlinModule()
        .registerModule(JavaTimeModule())

    override fun serialize(session: OidcSessionInformation?): ByteArray? {
        return session?.let { objectMapper.writeValueAsBytes(it) }
    }

    override fun deserialize(bytes: ByteArray?): OidcSessionInformation? {
        return bytes?.let { objectMapper.readValue(it, OidcSessionInformation::class.java) }
    }
} 
package by.sorface.gateway.config.serializer

import by.sorface.gateway.model.OidcSessionInformation
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.stereotype.Component

@Component
class OidcSessionInformationRedisSerializer : RedisSerializer<OidcSessionInformation> {

    private val objectMapper = ObjectMapper().apply {
        registerModule(JavaTimeModule())
        registerModule(KotlinModule.Builder().build())
    }

    override fun serialize(t: OidcSessionInformation?): ByteArray? {
        return t?.let { objectMapper.writeValueAsBytes(it) }
    }

    override fun deserialize(bytes: ByteArray?): OidcSessionInformation? {
        return bytes?.let { objectMapper.readValue(it, OidcSessionInformation::class.java) }
    }
} 
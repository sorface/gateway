package by.sorface.gateway.config.serializer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.stereotype.Component

@Component
class OAuth2AuthorizedClientRedisSerializer : RedisSerializer<OAuth2AuthorizedClient> {
    private val objectMapper: ObjectMapper = ObjectMapper()
        .registerKotlinModule()
        .registerModules(SecurityJackson2Modules.getModules(this.javaClass.classLoader))

    override fun serialize(client: OAuth2AuthorizedClient?): ByteArray? {
        return client?.let { objectMapper.writeValueAsBytes(it) }
    }

    override fun deserialize(bytes: ByteArray?): OAuth2AuthorizedClient? {
        return bytes?.let { objectMapper.readValue(it, OAuth2AuthorizedClient::class.java) }
    }
} 
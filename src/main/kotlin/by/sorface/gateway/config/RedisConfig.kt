package by.sorface.gateway.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.serializer.RedisSerializationContext
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator

@Configuration
@EnableRedisWebSession
class RedisConfig {

    @Bean
    fun reactiveRedisTemplate(
        connectionFactory: ReactiveRedisConnectionFactory
    ): ReactiveRedisTemplate<String, OAuth2AuthenticationToken> {
        val ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(OAuth2AuthenticationToken::class.java)
            .allowIfSubType(Map::class.java)
            .allowIfSubType(Collection::class.java)
            .allowIfSubType(String::class.java)
            .build()

        val objectMapper = ObjectMapper()
            .registerKotlinModule()
            .activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL)

        val tokenSerializer = object : RedisSerializer<OAuth2AuthenticationToken> {
            override fun serialize(token: OAuth2AuthenticationToken?): ByteArray? {
                return token?.let { objectMapper.writeValueAsBytes(it) }
            }

            override fun deserialize(bytes: ByteArray?): OAuth2AuthenticationToken? {
                return bytes?.let { objectMapper.readValue(it, OAuth2AuthenticationToken::class.java) }
            }
        }

        val stringSerializer = StringRedisSerializer()

        val context = RedisSerializationContext
            .newSerializationContext<String, OAuth2AuthenticationToken>()
            .key(stringSerializer)
            .value(tokenSerializer)
            .hashKey(stringSerializer)
            .hashValue(tokenSerializer)
            .build()

        return ReactiveRedisTemplate(connectionFactory, context)
    }
} 
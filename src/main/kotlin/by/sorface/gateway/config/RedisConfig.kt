package by.sorface.gateway.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.RedisSerializationContext
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule

@Configuration
@EnableRedisWebSession
class RedisConfig {

    @Bean
    fun reactiveRedisTemplate(
        connectionFactory: ReactiveRedisConnectionFactory
    ): ReactiveRedisTemplate<String, OAuth2AuthenticationToken> {
        val objectMapper = ObjectMapper()
            .registerKotlinModule()
            .registerModules(SecurityJackson2Modules.getModules(javaClass.classLoader))

        val serializer = Jackson2JsonRedisSerializer(objectMapper, OAuth2AuthenticationToken::class.java)

        val context = RedisSerializationContext
            .newSerializationContext<String, OAuth2AuthenticationToken>()
            .key(StringRedisSerializer())
            .value(serializer)
            .build()

        return ReactiveRedisTemplate(connectionFactory, context)
    }
} 
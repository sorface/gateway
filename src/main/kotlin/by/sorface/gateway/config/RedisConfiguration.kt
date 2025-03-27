package by.sorface.gateway.config

import by.sorface.gateway.dao.nosql.model.OAuth2AuthorizedClientModel
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import org.springframework.boot.autoconfigure.data.redis.RedisProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.connection.RedisConfiguration
import org.springframework.data.redis.connection.RedisStandaloneConfiguration
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.core.RedisKeyValueAdapter
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.RedisSerializationContext
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.session.SaveMode
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisIndexedWebSession

@Configuration
@EnableRedisIndexedWebSession(
    maxInactiveIntervalInSeconds = -1,
    redisNamespace = "gateway",
    saveMode = SaveMode.ON_SET_ATTRIBUTE
)
@EnableRedisRepositories(
    enableKeyspaceEvents = RedisKeyValueAdapter.EnableKeyspaceEvents.ON_STARTUP
)
class RedisConfiguration {

    @Bean
    fun redisStandaloneConfiguration(redisProperties: RedisProperties): RedisStandaloneConfiguration =
        RedisStandaloneConfiguration().apply {
            hostName = redisProperties.host
            port = redisProperties.port
            username = redisProperties.username
            setPassword(redisProperties.password)
        }

    @Bean
    fun lettuceConnectionFactory(redisStandaloneConfiguration: RedisConfiguration): LettuceConnectionFactory = LettuceConnectionFactory(redisStandaloneConfiguration)

    @Bean
    fun reactiveRedisTemplate(lettuceConnectionFactory: ReactiveRedisConnectionFactory, jackson2JsonRedisSerializer: Jackson2JsonRedisSerializer<OAuth2AuthorizedClientModel>): ReactiveRedisTemplate<String, OAuth2AuthorizedClientModel> {
        val keySerializer = StringRedisSerializer()

        val builder = RedisSerializationContext.newSerializationContext<String, OAuth2AuthorizedClientModel>(keySerializer)

        val context: RedisSerializationContext<String, OAuth2AuthorizedClientModel> = builder.value(jackson2JsonRedisSerializer)
            .key(keySerializer)
            .build()

        return ReactiveRedisTemplate(lettuceConnectionFactory, context)
    }

    @Bean
    fun jsonSerializer(): Jackson2JsonRedisSerializer<OAuth2AuthorizedClientModel> {
        val objectMapper = ObjectMapper()

        objectMapper.registerModule(JavaTimeModule())

        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)

        return Jackson2JsonRedisSerializer(objectMapper, OAuth2AuthorizedClientModel::class.java)
    }

}
package by.sorface.gateway.config

import by.sorface.gateway.dao.nosql.model.OAuth2AuthorizedClientModel
import by.sorface.gateway.dao.nosql.model.OidcRegistrationClient
import by.sorface.gateway.dao.nosql.model.converters.OidcSessionRedisSerializer
import by.sorface.gateway.dao.nosql.model.converters.OidcSessionBytesWritingConverter
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinFeature
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule
import org.springframework.boot.autoconfigure.data.redis.RedisProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.connection.RedisConfiguration
import org.springframework.data.redis.connection.RedisStandaloneConfiguration
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.core.RedisKeyValueAdapter
import org.springframework.data.redis.core.convert.RedisCustomConversions
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories
import org.springframework.data.redis.serializer.*
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
    fun reactiveAuthorizedClientRedisTemplate(
        lettuceConnectionFactory: ReactiveRedisConnectionFactory,
        jackson2JsonRedisSerializer: Jackson2JsonRedisSerializer<OAuth2AuthorizedClientModel>
    ): ReactiveRedisTemplate<String, OAuth2AuthorizedClientModel> {
        val keySerializer = StringRedisSerializer()

        val context = RedisSerializationContext.newSerializationContext<String, OAuth2AuthorizedClientModel>(keySerializer)
            .value(jackson2JsonRedisSerializer)
            .key(keySerializer)
            .build()

        return ReactiveRedisTemplate(lettuceConnectionFactory, context)
    }

    @Bean
    fun reactiveOidcRegistrationRedisTemplate(lettuceConnectionFactory: ReactiveRedisConnectionFactory): ReactiveRedisTemplate<String, OidcRegistrationClient> {
        val serializationContext = RedisSerializationContext
            .newSerializationContext<String, OidcRegistrationClient>(RedisSerializer.string())
            .hashValue(RedisSerializer.json())
            .hashValue(Jackson2JsonRedisSerializer(OidcRegistrationClient::class.java))
            .build()

        return ReactiveRedisTemplate(lettuceConnectionFactory, serializationContext)
    }

    @Bean
    fun jsonSerializer(): Jackson2JsonRedisSerializer<OAuth2AuthorizedClientModel> {
        val objectMapper = ObjectMapper()

        objectMapper.registerModule(JavaTimeModule())

        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)

        return Jackson2JsonRedisSerializer(objectMapper, OAuth2AuthorizedClientModel::class.java)
    }

}
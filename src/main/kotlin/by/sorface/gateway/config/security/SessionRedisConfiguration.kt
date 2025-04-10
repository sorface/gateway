package by.sorface.gateway.config.security

import by.sorface.gateway.dao.nosql.model.converters.ByteRedisSerializer
import org.springframework.boot.autoconfigure.data.redis.RedisProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.connection.RedisStandaloneConfiguration
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.serializer.RedisSerializationContext
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation

@Configuration
class SessionRedisConfiguration {

    @Bean
    fun lettuceConnectionFactory(redisProperties: RedisProperties): LettuceConnectionFactory {
        val redisStandaloneConfiguration = RedisStandaloneConfiguration().apply {
            hostName = redisProperties.host
            port = redisProperties.port
            username = redisProperties.username
            setPassword(redisProperties.password)
            database = redisProperties.database
        }

        return LettuceConnectionFactory(redisStandaloneConfiguration)
    }

    @Bean
    fun redisOidcSessionStoreClient(lettuceConnectionFactory: ReactiveRedisConnectionFactory): ReactiveRedisTemplate<String, OidcSessionInformation> {
        val context = RedisSerializationContext.newSerializationContext<String, OidcSessionInformation>(StringRedisSerializer())
            .value(ByteRedisSerializer<OidcSessionInformation>())
            .build()

        return ReactiveRedisTemplate(lettuceConnectionFactory, context)
    }

    @Bean
    fun redisOidcSessionIndexStoreClient(lettuceConnectionFactory: ReactiveRedisConnectionFactory): ReactiveRedisTemplate<String, String> {
        val stringRedisSerializer = StringRedisSerializer()

        val context = RedisSerializationContext.newSerializationContext<String, String>(stringRedisSerializer)
            .key(stringRedisSerializer)
            .hashKey(stringRedisSerializer)
            .build()

        return ReactiveRedisTemplate(lettuceConnectionFactory, context)
    }

    @Bean
    fun reactiveAuthorizedClientRedisTemplate(lettuceConnectionFactory: ReactiveRedisConnectionFactory): ReactiveRedisTemplate<String, OAuth2AuthorizedClient> {
        val keySerializer = StringRedisSerializer()

        val context = RedisSerializationContext.newSerializationContext<String, OAuth2AuthorizedClient>(keySerializer)
            .key(keySerializer)
            .value(ByteRedisSerializer<OAuth2AuthorizedClient>())
            .build()

        return ReactiveRedisTemplate(lettuceConnectionFactory, context)
    }

}
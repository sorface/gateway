package by.sorface.gateway.config

import by.sorface.gateway.dao.nosql.model.converters.OidcSessionRedisSerializer
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.serializer.RedisSerializationContext
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation

@Configuration
class RedisOidcSessionInformationConfiguration {

    @Bean
    fun redisOidcSessionStoreClient(
        lettuceConnectionFactory: ReactiveRedisConnectionFactory,
        objectMapper: ObjectMapper,
        oidcSessionRedisSerializer: OidcSessionRedisSerializer
    ): ReactiveRedisTemplate<String, OidcSessionInformation> {
        val context = RedisSerializationContext.newSerializationContext<String, OidcSessionInformation>(StringRedisSerializer())
            .value(oidcSessionRedisSerializer)
            .build()

        return ReactiveRedisTemplate(lettuceConnectionFactory, context)
    }

    @Bean
    fun redisOidcSessionIndexStoreClient(lettuceConnectionFactory: ReactiveRedisConnectionFactory): ReactiveRedisTemplate<String, String> {
        val keySerializer = StringRedisSerializer()

        val context = RedisSerializationContext.newSerializationContext<String, String>(keySerializer)
            .key(keySerializer)
            .hashKey(keySerializer)
            .build()

        return ReactiveRedisTemplate(lettuceConnectionFactory, context)
    }

}
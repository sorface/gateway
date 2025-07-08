package by.sorface.gateway.service

import by.sorface.gateway.config.serializer.OAuth2AuthorizedClientRedisSerializer
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.serializer.RedisSerializationContext
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import java.time.Duration

@Service
class RedisReactiveOAuth2AuthorizedClientService(
    redisConnectionFactory: ReactiveRedisConnectionFactory
) : ReactiveOAuth2AuthorizedClientService {

    private val redisTemplate: ReactiveRedisTemplate<String, OAuth2AuthorizedClient>

    init {
        val serializationContext = RedisSerializationContext
            .newSerializationContext<String, OAuth2AuthorizedClient>()
            .key(StringRedisSerializer())
            .value(OAuth2AuthorizedClientRedisSerializer())
            .build()

        redisTemplate = ReactiveRedisTemplate(redisConnectionFactory, serializationContext)
    }

    @Suppress("UNCHECKED_CAST")
    override fun <T : OAuth2AuthorizedClient> loadAuthorizedClient(
        clientRegistrationId: String,
        principalName: String
    ): Mono<T> {
        val key = generateKey(clientRegistrationId, principalName)
        return redisTemplate.opsForValue().get(key)
            .mapNotNull { it as? T }
    }

    override fun saveAuthorizedClient(
        authorizedClient: OAuth2AuthorizedClient,
        authentication: Authentication
    ): Mono<Void> {
        val key = generateKey(authorizedClient.clientRegistration.registrationId, authentication.name)
        return redisTemplate.opsForValue()
            .set(key, authorizedClient, Duration.ofDays(30))
            .then()
    }

    override fun removeAuthorizedClient(
        clientRegistrationId: String,
        principalName: String
    ): Mono<Void> {
        val key = generateKey(clientRegistrationId, principalName)
        return redisTemplate.opsForValue().delete(key).then()
    }

    private fun generateKey(clientRegistrationId: String, principalName: String): String {
        return "oauth2:client:$clientRegistrationId:$principalName"
    }
} 
package by.sorface.gateway.service

import by.sorface.gateway.config.serializer.OAuth2AuthorizedClientRedisSerializer
import org.slf4j.LoggerFactory
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.serializer.RedisSerializationContext
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class RedisReactiveOAuth2AuthorizedClientService(
    connectionFactory: ReactiveRedisConnectionFactory,
    oAuth2AuthorizedClientRedisSerializer: OAuth2AuthorizedClientRedisSerializer
) : ReactiveOAuth2AuthorizedClientService {

    private val logger = LoggerFactory.getLogger(javaClass)
    
    private val redisTemplate: ReactiveRedisTemplate<String, OAuth2AuthorizedClient> = ReactiveRedisTemplate(
        connectionFactory,
        RedisSerializationContext
            .newSerializationContext<String, OAuth2AuthorizedClient>()
            .key(StringRedisSerializer())
            .value(oAuth2AuthorizedClientRedisSerializer)
            .hashKey(StringRedisSerializer())
            .hashValue(oAuth2AuthorizedClientRedisSerializer)
            .build()
    )

    @Suppress("UNCHECKED_CAST")
    override fun <T : OAuth2AuthorizedClient> loadAuthorizedClient(
        clientRegistrationId: String,
        principalName: String
    ): Mono<T> {
        logger.debug("Loading authorized client for registration ID: $clientRegistrationId and principal: $principalName")
        val key = generateKey(clientRegistrationId, principalName)
        return redisTemplate.opsForValue().get(key)
            .doOnNext { logger.debug("Found authorized client: {}", it) }
            .doOnError { logger.error("Error loading authorized client", it) }
            .mapNotNull { it as T }
    }

    override fun saveAuthorizedClient(
        authorizedClient: OAuth2AuthorizedClient,
        principal: Authentication
    ): Mono<Void> {
        logger.debug("Saving authorized client for registration ID: ${authorizedClient.clientRegistration.registrationId}")
        val key = generateKey(authorizedClient.clientRegistration.registrationId, principal.name)
        return redisTemplate.opsForValue()
            .set(key, authorizedClient)
            .doOnSuccess { logger.debug("Successfully saved authorized client") }
            .doOnError { logger.error("Error saving authorized client", it) }
            .then()
    }

    override fun removeAuthorizedClient(
        clientRegistrationId: String,
        principalName: String
    ): Mono<Void> {
        logger.debug("Removing authorized client for registration ID: $clientRegistrationId and principal: $principalName")
        val key = generateKey(clientRegistrationId, principalName)
        return redisTemplate.opsForValue()
            .delete(key)
            .doOnSuccess { logger.debug("Successfully removed authorized client") }
            .doOnError { logger.error("Error removing authorized client", it) }
            .then()
    }

    private fun generateKey(clientRegistrationId: String, principalName: String): String {
        return "oauth2:clients:$clientRegistrationId:$principalName"
    }
} 
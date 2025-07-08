package by.sorface.gateway.service

import by.sorface.gateway.config.serializer.OidcSessionInformationRedisSerializer
import by.sorface.gateway.model.OidcSessionInformation
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.core.ScanOptions
import org.springframework.data.redis.serializer.RedisSerializationContext
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.stereotype.Service
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.time.Duration
import java.time.Instant

@Service
class RedisReactiveOidcSessionRegistry(redisConnectionFactory: ReactiveRedisConnectionFactory) {

    private lateinit var redisTemplate: ReactiveRedisTemplate<String, OidcSessionInformation>
    private lateinit var redisSetTemplate: ReactiveRedisTemplate<String, String>

    private val defaultDuration = Duration.ofDays(1)

    init {
        val serializationContext = RedisSerializationContext
            .newSerializationContext<String, OidcSessionInformation>()
            .key(StringRedisSerializer())
            .value(OidcSessionInformationRedisSerializer())
            .hashKey(StringRedisSerializer())
            .hashValue(OidcSessionInformationRedisSerializer())
            .build()

        val stringSerializationContext = RedisSerializationContext
            .newSerializationContext<String, String>()
            .key(StringRedisSerializer())
            .value(StringRedisSerializer())
            .hashKey(StringRedisSerializer())
            .hashValue(StringRedisSerializer())
            .build()

        redisTemplate = ReactiveRedisTemplate(redisConnectionFactory, serializationContext)
        redisSetTemplate = ReactiveRedisTemplate(redisConnectionFactory, stringSerializationContext)
    }

    fun saveSessionInformation(
        registrationId: String,
        principalName: String,
        sessionId: String,
        idToken: OidcIdToken
    ): Mono<Void> {
        val sessionInfo = OidcSessionInformation(
            principalName = principalName,
            sessionId = sessionId,
            registrationId = registrationId,
            issuedAt = idToken.issuedAt,
            expiresAt = idToken.expiresAt
        )

        val key = generateSessionKey(registrationId, principalName, sessionId)
        val principalKey = generatePrincipalKey(registrationId, principalName)
        val duration = idToken.expiresAt?.let { Duration.between(Instant.now(), it) } ?: defaultDuration

        return Mono.zip(
            redisTemplate.opsForValue().set(key, sessionInfo, duration),
            redisSetTemplate.opsForSet().add(principalKey, key)
        ).then()
    }

    fun removeSessionInformation(registrationId: String, principalName: String, sessionId: String): Mono<Void> {
        val key = generateSessionKey(registrationId, principalName, sessionId)
        val principalKey = generatePrincipalKey(registrationId, principalName)

        return Mono.zip(
            redisTemplate.opsForValue().delete(key),
            redisSetTemplate.opsForSet().remove(principalKey, key)
        ).then()
    }

    fun findByPrincipalName(registrationId: String, principalName: String): Flux<OidcSessionInformation> {
        val principalKey = generatePrincipalKey(registrationId, principalName)

        return redisSetTemplate.opsForSet().members(principalKey)
            .flatMap { sessionKey ->
                redisTemplate.opsForValue().get(sessionKey)
            }
    }

    fun findBySessionId(registrationId: String, sessionId: String): Mono<OidcSessionInformation> {
        val pattern = "oidc:sessions:$registrationId:*:$sessionId"
        return redisTemplate.scan(ScanOptions.scanOptions().match(pattern).build())
            .flatMap { key -> redisTemplate.opsForValue().get(key) }
            .next()
    }

    private fun generateSessionKey(registrationId: String, principalName: String, sessionId: String): String {
        return "oidc:sessions:$registrationId:$principalName:$sessionId"
    }

    private fun generatePrincipalKey(registrationId: String, principalName: String): String {
        return "oidc:principals:$registrationId:$principalName"
    }
} 
package by.sorface.gateway.service

import by.sorface.gateway.config.serializer.OidcSessionInformationRedisSerializer
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.data.redis.core.ScanOptions
import org.springframework.data.redis.serializer.RedisSerializationContext
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.stereotype.Service
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.time.Duration

const val REGISTRATION_ID_KEY_NAME = "registrationId"

const val PRINCIPAL_NAME_KEY_NAME = "principalName"

@Service
class RedisReactiveOidcSessionRegistry(
    connectionFactory: ReactiveRedisConnectionFactory,
    oidcSessionInformationRedisSerializer: OidcSessionInformationRedisSerializer
) : ReactiveOidcSessionRegistry {

    private val redisTemplate: ReactiveRedisTemplate<String, OidcSessionInformation> = ReactiveRedisTemplate(
        connectionFactory,
        RedisSerializationContext
            .newSerializationContext<String, OidcSessionInformation>()
            .key(StringRedisSerializer())
            .value(oidcSessionInformationRedisSerializer)
            .hashKey(StringRedisSerializer())
            .hashValue(oidcSessionInformationRedisSerializer)
            .build()
    )

    companion object {
        private const val KEY_PREFIX = "oidc:session:"
        private const val PRINCIPAL_KEY_PREFIX = "oidc:principal:"
    }

    override fun saveSessionInformation(info: OidcSessionInformation?): Mono<Void> {
        if (info == null) return Mono.empty()

        val sessionKey = getSessionKey(info.sessionId)
        val principalKey = getPrincipalKey(getPrincipalFromAuthorities(info), getRegistrationFromAuthorities(info), info.sessionId)
        val duration = Duration.ofHours(1) // Default duration since we can't access expiresAt easily

        return Mono.zip(
            redisTemplate.opsForValue().set(sessionKey, info, duration),
            redisTemplate.opsForValue().set(principalKey, info, duration)
        ).then()
    }

    fun saveSessionInformation(
        registrationId: String,
        principalName: String,
        sessionId: String,
        idToken: OidcIdToken
    ): Mono<Void> {
        val user = DefaultOidcUser(emptyList(), idToken)
        val authorities = mapOf(
            REGISTRATION_ID_KEY_NAME to registrationId,
            PRINCIPAL_NAME_KEY_NAME to principalName
        )
        val sessionInformation = OidcSessionInformation(sessionId, authorities, user)
        return saveSessionInformation(sessionInformation)
    }

    fun findByPrincipalName(registrationId: String, principalName: String): Flux<OidcSessionInformation> {
        val pattern = "$PRINCIPAL_KEY_PREFIX$principalName:$registrationId:*"
        return redisTemplate.scan(ScanOptions.scanOptions().match(pattern).build())
            .flatMap { key -> redisTemplate.opsForValue().get(key) }
            .filter { it != null }
    }

    override fun removeSessionInformation(clientSessionId: String?): Mono<OidcSessionInformation> {
        if (clientSessionId == null) return Mono.empty()
        
        val sessionKey = getSessionKey(clientSessionId)
        return redisTemplate.opsForValue().get(sessionKey)
            .filter { it != null }
            .flatMap { session ->
                removeSessionInformation(getRegistrationFromAuthorities(session), getPrincipalFromAuthorities(session), session.sessionId)
                    .thenReturn(session)
            }
    }

    override fun removeSessionInformation(logoutToken: OidcLogoutToken?): Flux<OidcSessionInformation> {
        if (logoutToken == null) return Flux.empty()
        
        return findByPrincipalName(logoutToken.issuer.toString(), logoutToken.subject)
            .flatMap { session ->
                removeSessionInformation(getRegistrationFromAuthorities(session), getPrincipalFromAuthorities(session), session.sessionId)
                    .thenReturn(session)
            }
    }

    private fun removeSessionInformation(
        registrationId: String,
        principalName: String,
        sessionId: String
    ): Mono<Void> {
        val sessionKey = getSessionKey(sessionId)
        val principalKey = getPrincipalKey(principalName, registrationId, sessionId)

        return Mono.zip(
            redisTemplate.delete(sessionKey),
            redisTemplate.delete(principalKey)
        ).then()
    }

    private fun getSessionKey(sessionId: String): String = "$KEY_PREFIX$sessionId"

    private fun getPrincipalKey(principalName: String, registrationId: String, sessionId: String): String =
        "$PRINCIPAL_KEY_PREFIX$principalName:$registrationId:$sessionId"

    private fun getPrincipalFromAuthorities(session: OidcSessionInformation): String =
        session.authorities[PRINCIPAL_NAME_KEY_NAME] ?: "unknown"

    private fun getRegistrationFromAuthorities(session: OidcSessionInformation): String =
        session.authorities[REGISTRATION_ID_KEY_NAME] ?: "default"
} 
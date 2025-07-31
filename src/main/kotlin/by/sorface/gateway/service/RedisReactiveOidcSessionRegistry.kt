package by.sorface.gateway.service

import by.sorface.gateway.config.serializer.OidcSessionInformationRedisSerializer
import org.slf4j.LoggerFactory
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

const val REGISTRATION_ID_KEY_NAME = "passport"
const val PRINCIPAL_NAME_KEY_NAME = "sub"

@Service
class RedisReactiveOidcSessionRegistry(
    connectionFactory: ReactiveRedisConnectionFactory,
    oidcSessionInformationRedisSerializer: OidcSessionInformationRedisSerializer
) : ReactiveOidcSessionRegistry {

    companion object {
        private const val KEY_PREFIX = "oidc:session:"
        private const val PRINCIPAL_KEY_PREFIX = "oidc:principal:"
        private val DEFAULT_DURATION = Duration.ofHours(120)
    }

    private val logger = LoggerFactory.getLogger(RedisReactiveOidcSessionRegistry::class.java)

    private val redisTemplate: ReactiveRedisTemplate<String, OidcSessionInformation> =
        ReactiveRedisTemplate(
            connectionFactory,
            RedisSerializationContext
                .newSerializationContext<String, OidcSessionInformation>()
                .key(StringRedisSerializer())
                .value(oidcSessionInformationRedisSerializer)
                .hashKey(StringRedisSerializer())
                .hashValue(oidcSessionInformationRedisSerializer)
                .build()
        )

    override fun saveSessionInformation(info: OidcSessionInformation?): Mono<Void> {
        if (info == null) {
            logger.debug("Attempt to save null session information")
            return Mono.empty()
        }

        logger.debug("Saving session information - Session ID: {}, Principal: {}", info.sessionId, info.principal.name)

        val sessionKey = getSessionKey(info.sessionId)

        val principalName = this.getPrincipalFromAuthorities(info)
        val registrationId = REGISTRATION_ID_KEY_NAME

        val principalKey = this.getPrincipalKey(principalName, registrationId, info.sessionId)

        // Используем время жизни из ID токена или дефолтное значение
        val duration = info.principal.let { principal ->
            when (principal) {
                is DefaultOidcUser -> {
                    val idToken = principal.idToken
                    if (idToken.expiresAt != null) {
                        Duration.between(idToken.issuedAt, idToken.expiresAt)
                    } else {
                        DEFAULT_DURATION
                    }
                }

                else -> DEFAULT_DURATION
            }
        }

        logger.debug("Setting session with duration: {} for keys - Session: {}, Principal: {}", duration, sessionKey, principalKey)

        return Mono.zip(
            redisTemplate.opsForValue().set(sessionKey, info, duration)
                .doOnSuccess { logger.debug("Successfully saved session information under key: {}", sessionKey) }
                .doOnError { e -> logger.error("Failed to save session information under key: {}", sessionKey, e) },
            redisTemplate.opsForValue().set(principalKey, info, duration)
                .doOnSuccess { logger.debug("Successfully saved principal information under key: {}", principalKey) }
                .doOnError { e -> logger.error("Failed to save principal information under key: {}", principalKey, e) }
        ).then()
    }

    fun saveSessionInformation(registrationId: String, principalName: String, sessionId: String, idToken: OidcIdToken): Mono<Void> {
        logger.debug("Creating new session information - Registration ID: {}, Principal: {}, Session ID: {}", registrationId, principalName, sessionId)

        val user = DefaultOidcUser(emptyList(), idToken)

        val authorities = mapOf(
            REGISTRATION_ID_KEY_NAME to registrationId,
            PRINCIPAL_NAME_KEY_NAME to principalName
        )

        val sessionInformation = OidcSessionInformation(sessionId, authorities, user)

        return saveSessionInformation(sessionInformation)
    }

    override fun removeSessionInformation(clientSessionId: String?): Mono<OidcSessionInformation> {
        if (clientSessionId == null) {
            logger.debug("Attempt to remove null session ID")

            return Mono.empty()
        }

        logger.debug("Removing session information for session ID: {}", clientSessionId)

        val sessionKey = getSessionKey(clientSessionId)
        return redisTemplate.opsForValue().get(sessionKey)
            .filter { it != null }
            .flatMap { session ->
                val registrationId = REGISTRATION_ID_KEY_NAME
                val principalName = getPrincipalFromAuthorities(session)

                logger.debug("Found session to remove - Registration ID: {}, Principal: {}", registrationId, principalName)

                removeSessionInformation(registrationId, principalName, session.sessionId)
                    .doOnSuccess { logger.debug("Successfully removed session information") }
                    .doOnError { e -> logger.error("Failed to remove session information", e) }
                    .thenReturn(session)
            }
    }

    override fun removeSessionInformation(logoutToken: OidcLogoutToken?): Flux<OidcSessionInformation> {
        if (logoutToken == null) {
            logger.debug("Attempt to remove sessions with null logout token")
            return Flux.empty()
        }

        logger.debug("Removing sessions for logout token - Issuer: {}, Subject: {}", logoutToken.issuer, logoutToken.subject)

        return findByPrincipalName(logoutToken.issuer.toString(), logoutToken.subject)
            .flatMap { session ->
                val registrationId = REGISTRATION_ID_KEY_NAME
                val principalName = this.getPrincipalFromAuthorities(session)

                this.removeSessionInformation(registrationId, principalName, session.sessionId).thenReturn(session)
            }
    }

    fun findByPrincipalName(registrationId: String, principalName: String): Flux<OidcSessionInformation> {
        logger.debug(
            "Finding sessions for principal - Registration ID: {}, Principal: {}",
            registrationId, principalName
        )

        val pattern = "$PRINCIPAL_KEY_PREFIX$principalName:$registrationId:*"
        return redisTemplate.scan(ScanOptions.scanOptions().match(pattern).build())
            .doOnNext { key -> logger.debug("Found key matching pattern: {}", key) }
            .flatMap { key ->
                redisTemplate.opsForValue().get(key)
                    .doOnNext { logger.debug("Retrieved session information for key: {}", key) }
            }
            .filter { it != null }
    }

    private fun removeSessionInformation(registrationId: String, principalName: String, sessionId: String): Mono<Void> {
        logger.debug("Removing session information - Registration ID: {}, Principal: {}, Session ID: {}", registrationId, principalName, sessionId)

        val sessionKey = getSessionKey(sessionId)
        val principalKey = getPrincipalKey(principalName, registrationId, sessionId)

        return Mono
            .zip(
                redisTemplate.opsForValue().delete(sessionKey).doOnSuccess { logger.debug("Deleted session key: {}", sessionKey) },
                redisTemplate.opsForValue().delete(principalKey).doOnSuccess { logger.debug("Deleted principal key: {}", principalKey) }
            )
            .then()
    }

    private fun getSessionKey(sessionId: String) = "$KEY_PREFIX$sessionId"

    private fun getPrincipalKey(principalName: String, registrationId: String, sessionId: String) =
        "$PRINCIPAL_KEY_PREFIX$principalName:$registrationId:$sessionId"

    private fun getRegistrationFromAuthorities(session: OidcSessionInformation): String =
        session.authorities[REGISTRATION_ID_KEY_NAME] ?: throw IllegalStateException("No registration ID in session")

    private fun getPrincipalFromAuthorities(session: OidcSessionInformation): String =
        session.principal.attributes[PRINCIPAL_NAME_KEY_NAME] as String? ?: throw IllegalStateException("No principal name in session")
} 
package by.sorface.gateway.config.security.repository

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.stereotype.Component
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.time.Duration

@Component
class RedisReactiveOidcSessionRepository(
    @Qualifier("redisOidcSessionStoreClient") private val redisOidcSessionStoreClient: ReactiveRedisTemplate<String, OidcSessionInformation>,
    @Qualifier("redisOidcSessionIndexStoreClient") private val redisOidcSessionIndexStoreClient: ReactiveRedisTemplate<String, String>,
    @Value("\${spring.session.timeout:30m}") private val sessionTimeout: Duration
) : ReactiveOidcSessionRegistry {

    private val logger = LoggerFactory.getLogger(RedisReactiveOidcSessionRepository::class.java)

    override fun saveSessionInformation(info: OidcSessionInformation): Mono<Void> {
        val sessionKey = getSessionKey(info.sessionId)
        val userKey = getUserKey(info.principal.subject)
        val issuerKey = getIssuerKey(info.principal.issuer.toString())

        return Mono.defer {
            logger.info("Starting OIDC session save: sessionId=[{}], subject=[{}], issuer=[{}], expiresIn=[{}]", 
                info.sessionId, info.principal.subject, info.principal.issuer, sessionTimeout)
            
            logger.debug("Saving OIDC session details - Claims: {}, Authorities: {}", 
                info.principal.claims, info.principal.authorities)
            
            // Сохраняем информацию о сессии
            redisOidcSessionStoreClient.opsForValue()
                .set(sessionKey, info, sessionTimeout)
                .then(
                    // Добавляем индекс по пользователю
                    redisOidcSessionIndexStoreClient.opsForSet()
                        .add(userKey, info.sessionId)
                        .then(redisOidcSessionIndexStoreClient.expire(userKey, sessionTimeout))
                        .doOnSuccess {
                            logger.debug("Added user index for subject=[{}]", info.principal.subject)
                        }
                )
                .then(
                    // Добавляем индекс по issuer
                    redisOidcSessionIndexStoreClient.opsForSet()
                        .add(issuerKey, info.sessionId)
                        .then(redisOidcSessionIndexStoreClient.expire(issuerKey, sessionTimeout))
                        .doOnSuccess {
                            logger.debug("Added issuer index for issuer=[{}]", info.principal.issuer)
                        }
                )
                .doOnSuccess { 
                    logger.info("Successfully saved OIDC session with all indexes: sessionId=[{}], subject=[{}]", 
                        info.sessionId, info.principal.subject)
                }
                .doOnError { error ->
                    logger.error("Failed to save OIDC session: sessionId=[{}], subject=[{}], error=[{}]", 
                        info.sessionId, info.principal.subject, error.message, error)
                }
                .then()
        }
    }

    override fun removeSessionInformation(clientSessionId: String): Mono<OidcSessionInformation> {
        val sessionKey = getSessionKey(clientSessionId)

        return Mono.defer {
            logger.info("Starting OIDC session removal: sessionId=[{}]", clientSessionId)

            redisOidcSessionStoreClient.opsForValue()
                .get(sessionKey)
                .doOnNext { session ->
                    logger.info("Found session to remove: sessionId=[{}], subject=[{}], issuer=[{}]",
                        clientSessionId, session.principal.subject, session.principal.issuer)
                }
                .flatMap { session ->
                    val userKey = getUserKey(session.principal.subject)
                    val issuerKey = getIssuerKey(session.principal.issuer.toString())
                    
                    // Удаляем сессию и все индексы
                    Mono.zip(
                        redisOidcSessionStoreClient.delete(sessionKey)
                            .doOnSuccess { logger.debug("Removed session data: sessionId=[{}]", clientSessionId) },
                        redisOidcSessionIndexStoreClient.opsForSet().remove(userKey, clientSessionId)
                            .doOnSuccess { logger.debug("Removed user index: subject=[{}]", session.principal.subject) },
                        redisOidcSessionIndexStoreClient.opsForSet().remove(issuerKey, clientSessionId)
                            .doOnSuccess { logger.debug("Removed issuer index: issuer=[{}]", session.principal.issuer) }
                    ).thenReturn(session)
                }
                .doOnSuccess { session -> 
                    logger.info("Successfully removed OIDC session and all indexes: sessionId=[{}], subject=[{}]", 
                        clientSessionId, session?.principal?.subject)
                }
                .doOnError { error ->
                    logger.error("Failed to remove OIDC session: sessionId=[{}], error=[{}]", 
                        clientSessionId, error.message, error)
                }
        }
    }

    override fun removeSessionInformation(logoutToken: OidcLogoutToken): Flux<OidcSessionInformation> {
        val userKey = getUserKey(logoutToken.subject)
        val issuerKey = getIssuerKey(logoutToken.issuer.toString())

        return Flux.defer {
            logger.info("Starting bulk OIDC sessions removal for subject=[{}], issuer=[{}], sid=[{}]", 
                logoutToken.subject, logoutToken.issuer, logoutToken.sessionId)

            // Находим все сессии пользователя для данного issuer
            redisOidcSessionIndexStoreClient.opsForSet()
                .intersect(userKey, issuerKey)
                .doOnNext { sessionId ->
                    logger.debug("Found session to remove in bulk operation: sessionId=[{}]", sessionId)
                }
                .flatMap { sessionId ->
                    removeSessionInformation(sessionId)
                }
                .doOnComplete {
                    logger.info("Successfully completed bulk removal of OIDC sessions for subject=[{}], issuer=[{}]", 
                        logoutToken.subject, logoutToken.issuer)
                }
                .doOnError { error ->
                    logger.error("Failed to remove OIDC sessions in bulk: subject=[{}], issuer=[{}], error=[{}]", 
                        logoutToken.subject, logoutToken.issuer, error.message, error)
                }
        }
    }

    private fun getSessionKey(sessionId: String): String = "oidc:session:$sessionId"
    
    private fun getUserKey(subject: String): String = "oidc:user:$subject"
    
    private fun getIssuerKey(issuer: String): String = "oidc:issuer:${issuer.replace(':', '_')}"
}
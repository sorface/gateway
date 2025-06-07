package by.sorface.gateway.config.security.repository

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.stereotype.Component
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

@Component
class RedisReactiveOidcSessionRepository(
    @Qualifier("redisOidcSessionStoreClient") private val redisOidcSessionStoreClient: ReactiveRedisTemplate<String, OidcSessionInformation>,
    @Qualifier("redisOidcSessionIndexStoreClient") private val redisOidcSessionIndexStoreClient: ReactiveRedisTemplate<String, String>
) : ReactiveOidcSessionRegistry {

    private val logger = LoggerFactory.getLogger(ReactiveOidcSessionRegistry::class.java)

    override fun saveSessionInformation(info: OidcSessionInformation): Mono<Void> {
        val oidcSessionKey = getKey(info.sessionId)

        logger.info("save session information with key [$oidcSessionKey]")

        return redisOidcSessionStoreClient.opsForSet().add(oidcSessionKey, info)
            .flatMap {
                val oidcIndexSessionKey = getKey(info.principal.userInfo.nickName)

                logger.info("save session information [$oidcSessionKey] index with user [$oidcIndexSessionKey]")

                redisOidcSessionIndexStoreClient.opsForSet().add(oidcIndexSessionKey, info.sessionId)
            }
            .doOnNext {
                logger.info("success save session information with key [$oidcSessionKey]. result -> $it")
            }
            .then()
    }

    override fun removeSessionInformation(clientSessionId: String): Mono<OidcSessionInformation> {
        val oidcIndexSessionKey = getKey(clientSessionId)

        logger.info("remove session information by client session id [$oidcIndexSessionKey]")

        return redisOidcSessionIndexStoreClient.opsForSet().members(oidcIndexSessionKey)
            .flatMap { sessionId ->
                val oidcSessionKey = getKey(sessionId)

                redisOidcSessionStoreClient.opsForSet().members(oidcSessionKey)
            }
            .flatMap { session ->
                val oidcSessionKey = getKey(session.sessionId)

                logger.info("remove session information by session id [$oidcSessionKey]")

                redisOidcSessionStoreClient.opsForSet().delete(oidcSessionKey).then(Mono.just(session))
            }
            .next()
    }

    override fun removeSessionInformation(logoutToken: OidcLogoutToken): Flux<OidcSessionInformation> {
        val oidcIndexSessionKey = getKey(logoutToken.subject)

        logger.info("remove session information by logout token by subject [$oidcIndexSessionKey]")

        return redisOidcSessionIndexStoreClient.opsForSet().members(oidcIndexSessionKey)
            .flatMap { getOidcSessionInformation(it.toString()) }
            .flatMap { session ->
                logger.info("remove session information by logout token with session id ${session.sessionId}")

                removeOidcSessionInformation(session.sessionId).then(Mono.just(session))
            }
    }

    private fun getOidcSessionInformation(id: String): Flux<OidcSessionInformation> {
        val oidcSessionKey = getKey(id)

        return redisOidcSessionStoreClient.opsForSet().members(oidcSessionKey)
            .flatMap { Mono.just(it) }
            .flatMap {
                val oidcIndexSessionKey = getKey(it.principal.subject)

                redisOidcSessionIndexStoreClient.opsForSet().delete(oidcIndexSessionKey).then(Mono.just(it)) }
            .onErrorResume {
                logger.error(it.message, it)
                Mono.error(RuntimeException(it))
            }
            .switchIfEmpty(Mono.defer {
                logger.error("empty")
                Mono.empty()
            })
    }

    private fun removeOidcSessionInformation(id: String): Mono<Boolean> {
        val key = getKey(id)

        return redisOidcSessionStoreClient.opsForSet().delete(key)
            .onErrorResume {
                Mono.error(RuntimeException(it))
            }
    }

    private fun getKey(id: String): String {
        return "oidc:session:$id"
    }

}
package by.sorface.gateway.config.repository

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.session.ReactiveFindByIndexNameSessionRepository
import org.springframework.session.Session
import org.springframework.session.data.redis.ReactiveRedisIndexedSessionRepository
import org.springframework.stereotype.Component
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

@Component
class RedisReactiveOidcSessionRepository(
    @Qualifier("redisOidcSessionStoreClient") private val redisOidcSessionStoreClient: ReactiveRedisTemplate<String, OidcSessionInformation>,
    @Qualifier("redisOidcSessionIndexStoreClient") private val redisOidcSessionIndexStoreClient: ReactiveRedisTemplate<String, String>,
    private val reactiveRedisIndexedSessionRepository: ReactiveRedisIndexedSessionRepository,
    private val findByIndexNameSessionRepository: ReactiveFindByIndexNameSessionRepository<out Session>
) : ReactiveOidcSessionRegistry {

    private val logger = LoggerFactory.getLogger(ReactiveOidcSessionRegistry::class.java)

    override fun saveSessionInformation(info: OidcSessionInformation): Mono<Void> {
        return redisOidcSessionStoreClient.opsForSet().add("oidc:session:${info.sessionId}", info)
            .flatMap { redisOidcSessionIndexStoreClient.opsForSet().add("oidc:session:${info.principal.userInfo.nickName}", info.sessionId) }
            .then()
    }

    override fun removeSessionInformation(clientSessionId: String): Mono<OidcSessionInformation> {
        return redisOidcSessionIndexStoreClient.opsForSet().members("oidc:session:${clientSessionId}")
            .flatMap { redisOidcSessionStoreClient.opsForSet().members("oidc:session:${it}") }
            .flatMap { redisOidcSessionStoreClient.opsForSet().delete("oidc:session:${it}").then(Mono.just(it)) }
            .next()
    }

    override fun removeSessionInformation(logoutToken: OidcLogoutToken): Flux<OidcSessionInformation> {
        return findByIndexNameSessionRepository.findByPrincipalName(logoutToken.subject)
            .flatMap { Mono.just(it.keys) }
            .flatMapMany { Flux.fromIterable(it) }
            .flatMap { id -> reactiveRedisIndexedSessionRepository.deleteById(id) }
            .flatMap { redisOidcSessionIndexStoreClient.opsForSet().members("oidc:session:${logoutToken.subject}") }
            .flatMap { getOidcSessionInformation(it.toString()) }
            .flatMap { session -> removeOidcSessionInformation(session.sessionId).then(Mono.just(session)) }
            .onErrorResume {
                Mono.error(RuntimeException(it))
            }
    }

    private fun getOidcSessionInformation(id: String): Flux<OidcSessionInformation> {
        return redisOidcSessionStoreClient.opsForSet().members("oidc:session:${id}")
            .flatMap { Mono.just(it) }
            .flatMap { redisOidcSessionIndexStoreClient.opsForSet().delete("oidc:session:${it.principal.subject}").then(Mono.just(it)) }
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
        return redisOidcSessionStoreClient.opsForSet().delete("oidc:session:${id}")
            .onErrorResume {
                Mono.error(RuntimeException(it))
            }
    }
}
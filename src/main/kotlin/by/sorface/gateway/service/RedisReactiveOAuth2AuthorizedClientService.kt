package by.sorface.gateway.service

import org.slf4j.LoggerFactory
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class RedisReactiveOAuth2AuthorizedClientService(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val reactiveAuthorizedClientRedisTemplate: ReactiveRedisTemplate<String, OAuth2AuthorizedClient>
) : ReactiveOAuth2AuthorizedClientService {

    private val logger = LoggerFactory.getLogger(this::class.java)

    @Suppress("UNCHECKED_CAST")
    override fun <T : OAuth2AuthorizedClient?> loadAuthorizedClient(clientRegistrationId: String, principalName: String): Mono<T> {
        return this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
            .switchIfEmpty(Mono.defer {
                val dataRetrievalFailureException = dataRetrievalFailureException(clientRegistrationId)

                logger.warn(
                    "failure load authorized client by client registration id [$clientRegistrationId] and principal name [$principalName]. {}",
                    dataRetrievalFailureException.message
                )

                Mono.error(dataRetrievalFailureException)
            })
            .flatMap<T> { clientRegistration ->
                val key = buildKey(clientRegistration.registrationId, principalName)

                logger.info("load authorized client by client registration id [$clientRegistrationId] and principal name [$principalName]")

                reactiveAuthorizedClientRedisTemplate.opsForValue().get(key).map { it as T }
            }
    }

    private fun dataRetrievalFailureException(clientRegistrationId: String): Throwable {
        return DataRetrievalFailureException(
            ("The ClientRegistration with id '" + clientRegistrationId
                    + "' exists in the data source, however, it was not found in the ReactiveClientRegistrationRepository.")
        )
    }

    override fun saveAuthorizedClient(authorizedClient: OAuth2AuthorizedClient, principal: Authentication): Mono<Void> {
        return this.clientRegistrationRepository.findByRegistrationId(authorizedClient.clientRegistration.registrationId)
            .switchIfEmpty(Mono.defer {
                logger.info(
                    "save authorized client not found because client registration not found by id " +
                            "[${authorizedClient.clientRegistration.registrationId}] for principal [name -> ${principal.name}]"
                )
                Mono.empty()
            })
            .flatMap { clientRegistration ->
                val key = buildKey(clientRegistration.registrationId, principal.name)

                logger.info("save authorized client with client registration id [${clientRegistration.registrationId}] and " +
                        "principal [name -> ${principal.name}]")

                reactiveAuthorizedClientRedisTemplate.opsForValue().set(key, authorizedClient)
            }
            .then()
    }

    override fun removeAuthorizedClient(clientRegistrationId: String, principalName: String): Mono<Void> {
        return reactiveAuthorizedClientRedisTemplate.opsForValue()
            .delete(buildKey(clientRegistrationId, principalName))
            .doOnNext { result ->
                logger.info("remove authorized client with client registration id [${clientRegistrationId}] and principal [$principalName] was been with result $result")
            }
            .then()
    }

    private fun buildKey(clientRegistrationId: String, principalName: String): String = "${clientRegistrationId}_${principalName}"

}
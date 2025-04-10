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

    @Suppress("UNCHECKED_CAST")
    override fun <T : OAuth2AuthorizedClient?> loadAuthorizedClient(clientRegistrationId: String, principalName: String): Mono<T> {
        return this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
            .switchIfEmpty(Mono.error(dataRetrievalFailureException(clientRegistrationId)))
            .flatMap<T> { clientRegistration ->
                val key = buildKey(clientRegistration.registrationId, principalName)
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
            .switchIfEmpty(Mono.empty())
            .flatMap { clientRegistration ->
                val key = buildKey(clientRegistration.registrationId, principal.name)
                reactiveAuthorizedClientRedisTemplate.opsForValue().set(key, authorizedClient)
            }
            .then()
    }

    override fun removeAuthorizedClient(clientRegistrationId: String, principalName: String): Mono<Void> {
        return reactiveAuthorizedClientRedisTemplate.opsForValue()
            .delete(buildKey(clientRegistrationId, principalName))
            .then()
    }

    private fun buildKey(clientRegistrationId: String, principalName: String): String = "${clientRegistrationId}_${principalName}"

}
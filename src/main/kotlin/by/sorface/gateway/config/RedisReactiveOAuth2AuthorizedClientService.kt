package by.sorface.gateway.config

import by.sorface.gateway.dao.nosql.model.OAuth2AuthorizedClientModel
import org.slf4j.LoggerFactory
import org.springframework.dao.DataRetrievalFailureException
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class RedisReactiveOAuth2AuthorizedClientService(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val lettuceRedisTemplate: ReactiveRedisTemplate<String, OAuth2AuthorizedClientModel>
) : ReactiveOAuth2AuthorizedClientService {

    private val log = LoggerFactory.getLogger(RedisReactiveOAuth2AuthorizedClientService::class.java)

    override fun <T : OAuth2AuthorizedClient?> loadAuthorizedClient(clientRegistrationId: String, principalName: String): Mono<T> {
        return this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
            .switchIfEmpty(Mono.error(dataRetrievalFailureException(clientRegistrationId)))
            .doOnNext {
                log.info("load registration application with id ${it.registrationId} and principal name $principalName")
            }
            .flatMap<T> { clientRegistration ->
                val key = buildKey(clientRegistrationId, principalName)

                lettuceRedisTemplate.opsForValue().get(key)
                    .flatMap { clientModel ->
                        log.info("load authorized client from nosql database for [${clientModel.principalName}]")

                        val authorizedClient = buildAuthorizedClientModel<T & Any>(clientRegistration, clientModel)

                        Mono.just(authorizedClient)
                    }
            }.doOnError {
                log.error("load authorized client for [$principalName] failed", it)
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
            .doOnNext {
                log.info("got registration application with id [${it.registrationId}]")
            }
            .flatMap { clientRegistration ->
                val key = buildKey(clientRegistration.registrationId, principal.name)

                val oAuth2AuthorizedClientModel = buildAuthorizedClientModel(key, principal.name, clientRegistration, authorizedClient)

                return@flatMap lettuceRedisTemplate.opsForValue().set(key, oAuth2AuthorizedClientModel)
                    .doOnNext {
                        log.info("authorization client for [${principal.name}] saved")
                    }
            }
            .doOnError {
                log.error("save authorized client failed. principal name [${principal.name}]", it)
            }
            .then()
    }

    override fun removeAuthorizedClient(clientRegistrationId: String, principalName: String): Mono<Void> {
        return lettuceRedisTemplate.opsForValue()
            .delete(buildKey(clientRegistrationId, principalName))
            .doOnNext {
                log.info("remove authorization client for [$principalName] and application IDP [$clientRegistrationId]")
            }
            .doOnError {
                log.info("remove authorization client for $principalName and application IDP [$clientRegistrationId] failed", it)
            }
            .then()
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T : OAuth2AuthorizedClient?> buildAuthorizedClientModel(clientRegistration: ClientRegistration, clientModel: OAuth2AuthorizedClientModel): T {
        val oAuth2AccessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            clientModel.accessTokenValue,
            clientModel.accessTokenIssuedAt,
            clientModel.accessTokenExpiresAt,
            clientModel.accessTokenScopes?.split(",")?.filterNot { it.isBlank() }?.map { it.trim() }?.toSet()
        )

        val oAuth2RefreshToken = OAuth2RefreshToken(clientModel.refreshTokenValue, clientModel.refreshTokenIssuedAt)

        return OAuth2AuthorizedClient(
            clientRegistration,
            clientModel.principalName,
            oAuth2AccessToken,
            oAuth2RefreshToken
        ) as T
    }

    private fun buildAuthorizedClientModel(id: String, principalName: String, clientModel: ClientRegistration, authorizedClient: OAuth2AuthorizedClient): OAuth2AuthorizedClientModel {
        return OAuth2AuthorizedClientModel().apply {
            this.id = id
            clientRegistrationId = clientModel.registrationId
            this.principalName = principalName
            accessTokenType = authorizedClient.accessToken.tokenType.value
            accessTokenValue = authorizedClient.accessToken.tokenValue
            accessTokenIssuedAt = authorizedClient.accessToken.issuedAt
            accessTokenExpiresAt = authorizedClient.accessToken.expiresAt
            accessTokenScopes = authorizedClient.accessToken.scopes.filterNot { it.isBlank() }.joinToString { it }
            refreshTokenValue = authorizedClient.refreshToken?.tokenValue
            refreshTokenIssuedAt = authorizedClient.refreshToken?.issuedAt
        }
    }

    private fun buildKey(clientRegistrationId: String, principalName: String): String = "${clientRegistrationId}_${principalName}"

}
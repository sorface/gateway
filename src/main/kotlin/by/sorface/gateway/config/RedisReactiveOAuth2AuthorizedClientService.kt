package by.sorface.gateway.config

import by.sorface.gateway.dao.nosql.model.OAuth2AuthorizedClientModel
import org.slf4j.LoggerFactory
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import reactor.core.publisher.Mono

// @Service
class RedisReactiveOAuth2AuthorizedClientService(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository,
    private val lettuceRedisTemplate: ReactiveRedisTemplate<String, OAuth2AuthorizedClientModel>
) : ReactiveOAuth2AuthorizedClientService {

    private val log = LoggerFactory.getLogger(RedisReactiveOAuth2AuthorizedClientService::class.java)

    override fun <T : OAuth2AuthorizedClient?> loadAuthorizedClient(clientRegistrationId: String, principalName: String): Mono<T> {
        return this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
            .log("got registration application client by $clientRegistrationId")
            .switchIfEmpty(Mono.empty())
            .log("get current authorized client for $principalName")
            .flatMap { clientRegistration ->
                lettuceRedisTemplate.opsForValue().get("${clientRegistrationId}_${principalName}")
                    .flatMap { Mono.just(map(clientRegistration, it)) }
            }
    }

    override fun saveAuthorizedClient(authorizedClient: OAuth2AuthorizedClient, principal: Authentication): Mono<Void> {
        return this.clientRegistrationRepository.findByRegistrationId(authorizedClient.clientRegistration.registrationId)
            .switchIfEmpty(Mono.empty())
            .flatMap { clientRegistration ->
                val oAuth2AuthorizedClientModel =
                    map("${clientRegistration.registrationId}_${principal.name}", principal.name, clientRegistration, authorizedClient)

                return@flatMap lettuceRedisTemplate.opsForValue().set("${clientRegistration.registrationId}_${principal.name}", oAuth2AuthorizedClientModel)
                    .doOnError {
                        log.error("error occurred while saving authorization client for $principal. ${it.message}")
                    }
            }
            .doOnError {
                log.error("error occurred while saving authorization client ${it.message}")
            }
            .then()
    }

    override fun removeAuthorizedClient(clientRegistrationId: String, principalName: String): Mono<Void> {
        return lettuceRedisTemplate.opsForValue()
            .delete("${clientRegistrationId}_${principalName}")
            .log("remove authorization client for $principalName and application IDP $clientRegistrationId")
            .then()
    }

    private fun <T : OAuth2AuthorizedClient?> map(clientRegistration: ClientRegistration, clientModel: OAuth2AuthorizedClientModel): T {
        val oAuth2AccessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            clientModel.accessTokenValue,
            clientModel.accessTokenIssuedAt,
            clientModel.accessTokenExpiresAt,
            clientModel.accessTokenScopes?.split(",")?.toSet()
        )

        val oAuth2RefreshToken = OAuth2RefreshToken(clientModel.refreshTokenValue, clientModel.refreshTokenIssuedAt)

        return OAuth2AuthorizedClient(
            clientRegistration,
            clientModel.principalName,
            oAuth2AccessToken,
            oAuth2RefreshToken
        ) as T
    }

    private fun map(id: String, principalName: String, clientModel: ClientRegistration, authorizedClient: OAuth2AuthorizedClient): OAuth2AuthorizedClientModel {
        return OAuth2AuthorizedClientModel().apply {
            this.id = id
            clientRegistrationId = clientModel.registrationId
            this.principalName = principalName
            accessTokenType = authorizedClient.accessToken.tokenType.value
            accessTokenValue = authorizedClient.accessToken.tokenValue
            accessTokenIssuedAt = authorizedClient.accessToken.issuedAt
            accessTokenExpiresAt = authorizedClient.accessToken.expiresAt
            accessTokenScopes = authorizedClient.accessToken.scopes.joinToString { "," }
            refreshTokenValue = authorizedClient.refreshToken?.tokenValue
            refreshTokenIssuedAt = authorizedClient.refreshToken?.issuedAt
        }
    }

}
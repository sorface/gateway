package by.sorface.gateway.config.repository

import by.sorface.gateway.dao.nosql.model.OidcRegistrationClient
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.core.AuthorizationGrantType.*
import org.springframework.security.oauth2.core.ClientAuthenticationMethod.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets

class DynamicReactiveClientRegistrationRepository(
    private val webClient: WebClient,
    private val staticRegistrations: MutableMap<String, ClientRegistration>,
    private val redisReactiveOidcSessionRepository: ReactiveRedisTemplate<String, OidcRegistrationClient>
) : ReactiveClientRegistrationRepository {

    private fun doRegistration(id: String): Mono<ClientRegistration> {
        val clientRegistration: ClientRegistration = staticRegistrations[id] ?: return Mono.empty()

        return this.getAccessToken(clientRegistration)
            .flatMap { token  -> dynamicRegistrationClient(token, clientRegistration) }
    }

    override fun findByRegistrationId(registrationId: String): Mono<ClientRegistration> {
        return redisReactiveOidcSessionRepository.opsForHash<String, OidcRegistrationClient>()
            .get("oidc:registration:client:$registrationId", registrationId)
            .flatMap { oidcRegistrationClient ->
                return@flatMap Mono.just(mapToClientRegistration(oidcRegistrationClient))
            }
            .switchIfEmpty(doRegistration(registrationId))
    }

    private fun dynamicRegistrationClient(oauthToken: OAuth2ClientAccessToken, clientRegistration: ClientRegistration): Mono<ClientRegistration> {
        val body = mapOf(
            "client_name" to clientRegistration.clientName,
            "redirect_uris" to listOf(clientRegistration.redirectUri),
            "client_authorization_method" to listOf(
                CLIENT_SECRET_BASIC, CLIENT_SECRET_POST, CLIENT_SECRET_JWT
            ),
            "post_logout_redirect_uris" to listOf("http://localhost:3000", "http://localhost:9030", "http://localhost:8080"),
            "grant_types" to listOf(CLIENT_CREDENTIALS.value, AUTHORIZATION_CODE.value, REFRESH_TOKEN.value),
            "scope" to clientRegistration.scopes.joinToString(" ")
        )

        return webClient.post()
            .uri("${clientRegistration.providerDetails.issuerUri}/connect/register")
            .header(HttpHeaders.AUTHORIZATION, "${oauthToken.tokenType} ${oauthToken.accessToken}")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(body)
            .exchangeToMono { response -> response.bodyToMono(ClientRegistrationResponse::class.java) }
            .flatMap { dynamicClientRegistration ->
                val oidcRegistration = map(clientRegistration, dynamicClientRegistration)

                return@flatMap redisReactiveOidcSessionRepository.opsForHash<String, OidcRegistrationClient>()
                    .put("oidc:registration:client:${clientRegistration.registrationId}", clientRegistration.registrationId, oidcRegistration)
                    .flatMap { Mono.just(mapToClientRegistration(clientRegistration.registrationId, dynamicClientRegistration)) }
            }
    }

    private fun getAccessToken(clientRegistration: ClientRegistration): Mono<OAuth2ClientAccessToken> {
        val formData = LinkedMultiValueMap<String, String>().apply {
            add(OAuth2ParameterNames.GRANT_TYPE, CLIENT_CREDENTIALS.value)
            add(OAuth2ParameterNames.SCOPE, "client.create")
        }

        return webClient.post()
            .uri("${clientRegistration.providerDetails.issuerUri}/oauth2/token")
            .header(HttpHeaders.AUTHORIZATION, buildBasicAuth(clientRegistration.clientId, clientRegistration.clientSecret))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData(formData))
            .exchangeToMono { response -> response.bodyToMono(OAuth2ClientAccessToken::class.java) }
    }

    private fun buildBasicAuth(clientId: String, clientSecret: String, charset: Charset = StandardCharsets.UTF_8): String {
        return "Basic ${HttpHeaders.encodeBasicAuth(clientId, clientSecret, charset)}"
    }

    private fun map(clientRegistration: ClientRegistration, response: ClientRegistrationResponse): OidcRegistrationClient {
        return OidcRegistrationClient().apply {
            this.id = clientRegistration.registrationId
            this.clientId = response.clientId
            this.clientName = response.clientName
            this.clientSecret = response.clientSecret
            this.clientUri = response.registrationClientUri
            this.grantTypes = response.grantTypes
            this.scopes = response.scope.split(" ")
                .map { it.trim() }
                .toList()
            this.redirectUris = response.redirectUris
            this.registrationUrl = response.registrationClientUri
            this.registrationToken = response.registrationAccessToken
        }
    }

    private fun mapToClientRegistration(id: String, response: ClientRegistrationResponse): ClientRegistration {
        val authorizationGrantTypes = response.grantTypes.map {
            return@map when (it) {
                "authorization_code" -> AUTHORIZATION_CODE
                "refresh_token" -> REFRESH_TOKEN
                "client_credentials" -> CLIENT_CREDENTIALS
                else -> AUTHORIZATION_CODE
            }
        }

        val scopes = response.scope.split(" ")
            .map { it.trim() }
            .toList()

        return ClientRegistration.withRegistrationId(id)
            .clientId(response.clientId)
            .clientName(response.clientName)
            .clientSecret(response.clientSecret)
            .redirectUri(response.redirectUris.firstOrNull())
            .authorizationGrantType(authorizationGrantTypes.firstOrNull())
            .scope(scopes)
            .build()
    }

    private fun mapToClientRegistration(oidcRegistrationClient: OidcRegistrationClient): ClientRegistration {
        return ClientRegistration.withRegistrationId(oidcRegistrationClient.id)
            .clientId(oidcRegistrationClient.clientId)
            .clientName(oidcRegistrationClient.clientName)
            .clientSecret(oidcRegistrationClient.clientSecret)
            .redirectUri(oidcRegistrationClient.redirectUris.firstOrNull())
            .authorizationGrantType(AUTHORIZATION_CODE)
            .build()
    }

    @JvmRecord
    data class ClientRegistrationResponse(
        @JsonProperty("registration_access_token")
        val registrationAccessToken: String,

        @JsonProperty("registration_client_uri")
        val registrationClientUri: String,

        @JsonProperty("client_name")
        val clientName: String,

        @JsonProperty("client_id")
        val clientId: String,

        @JsonProperty("client_secret")
        val clientSecret: String,

        @JsonProperty("grant_types")
        val grantTypes: List<String>,

        @JsonProperty("redirect_uris")
        val redirectUris: List<String>,

        val scope: String
    )

    private data class OAuth2ClientAccessToken(
        @JsonProperty("access_token")
        val accessToken: String,

        val scope: String,
        @JsonProperty("token_type")

        val tokenType: String,
        @JsonProperty("expires_in")

        val expiresIn: Int
    )
}
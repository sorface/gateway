package by.sorface.gateway.service

import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.time.Duration
import java.time.Instant

@Service
class TokenRefreshService(
    private val authorizedClientService: ReactiveOAuth2AuthorizedClientService,
    private val webClientBuilder: WebClient.Builder
) {

    private val logger = LoggerFactory.getLogger(TokenRefreshService::class.java)

    /**
     * Refreshes the token if needed and, when an ID token is returned by the provider,
     * updates the current SecurityContext with a new OAuth2AuthenticationToken that reflects
     * the refreshed OIDC principal.
     */
    fun refreshTokenAndUpdateAuthenticationIfNeeded(authentication: OAuth2AuthenticationToken, exchange: ServerWebExchange): Mono<OAuth2AuthenticationToken?> {
        val clientRegistrationId = authentication.authorizedClientRegistrationId
        val principalName = authentication.name

        return authorizedClientService.loadAuthorizedClient<OAuth2AuthorizedClient>(clientRegistrationId, principalName)
            .flatMap { authorizedClient -> refreshTokenDetailed(authorizedClient, authentication) }
            .flatMap { result ->
                val idTokenValue = result.idToken

                if (idTokenValue.isNullOrBlank()) {
                    return@flatMap Mono.empty()
                }

                val jwkSetUri = result.authorizedClient.clientRegistration.providerDetails.jwkSetUri
                val jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build()

                return@flatMap jwtDecoder.decode(idTokenValue)
                    .flatMap jwtMapper@{ jwt ->
                        val oidcIdToken = OidcIdToken(idTokenValue, jwt.issuedAt, jwt.expiresAt, jwt.claims)
                        val oidcUserInfo = OidcUserInfo(jwt.claims)
                        val newPrincipal = DefaultOidcUser(authentication.authorities, oidcIdToken, oidcUserInfo)

                        val oAuth2AuthenticationToken = OAuth2AuthenticationToken(
                            newPrincipal,
                            authentication.authorities,
                            authentication.authorizedClientRegistrationId
                        )

                        return@jwtMapper Mono.just(oAuth2AuthenticationToken)
                    }
                    .onErrorResume { err ->
                        logger.warn("Failed to decode ID token during refresh: ${err.message}")
                        Mono.error(err)
                    }
            }
            .switchIfEmpty(Mono.error(RuntimeException("No authorized client found for $clientRegistrationId")))
    }

    private fun shouldRefreshToken(authorizedClient: OAuth2AuthorizedClient): Boolean {
        val accessToken = authorizedClient.accessToken
        val refreshToken = authorizedClient.refreshToken

        // If no refresh token is available, we can't refresh
        if (refreshToken == null) {
            logger.debug("No refresh token available for token refresh")
            return false
        }

        // If access token is null or expired, we should refresh
        if (accessToken == null) {
            logger.debug("Access token is null, refresh needed")
            return true
        }

        val expiresAt = accessToken.expiresAt
        if (expiresAt == null) {
            logger.debug("Access token has no expiry, assuming it's valid")
            return false
        }

        // Refresh if token expires within the next 5 minutes
        val refreshThreshold = Instant.now().plus(Duration.ofMinutes(1))
        val shouldRefresh = expiresAt.isBefore(refreshThreshold)

        if (shouldRefresh) {
            logger.debug("Access token expires at [{}], which is within refresh threshold [{}]", expiresAt, refreshThreshold)
        }

        return shouldRefresh
    }

    private fun refreshTokenDetailed(authorizedClient: OAuth2AuthorizedClient, authentication: OAuth2AuthenticationToken): Mono<RefreshedResult> {
        val refreshToken = authorizedClient.refreshToken

        if (refreshToken == null) {
            logger.warn("Cannot refresh token: no refresh token available")
            return Mono.just(RefreshedResult(authorizedClient, null))
        }

        val clientRegistration = authorizedClient.clientRegistration
        val tokenUri = clientRegistration.providerDetails.tokenUri

        return webClientBuilder.build()
            .post()
            .uri(tokenUri)
            .headers { headers ->
                headers.setBasicAuth(clientRegistration.clientId, clientRegistration.clientSecret)
                headers.add("Content-Type", "application/x-www-form-urlencoded")
            }
            .bodyValue(buildRefreshTokenRequest(refreshToken.tokenValue))
            .retrieve()
            .bodyToMono(TokenResponse::class.java)
            .flatMap { tokenResponse ->
                val newAccessToken = OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    tokenResponse.access_token,
                    Instant.now(),
                    Instant.now().plusSeconds(tokenResponse.expires_in ?: 3600)
                )

                // Prefer a newly issued refresh token if present
                val resultingRefreshToken = tokenResponse.refresh_token?.let { OAuth2RefreshToken(it, Instant.now()) } ?: refreshToken

                val newAuthorizedClient = OAuth2AuthorizedClient(
                    clientRegistration,
                    authentication.name,
                    newAccessToken,
                    resultingRefreshToken
                )

                authorizedClientService.saveAuthorizedClient(newAuthorizedClient, authentication)
                    .then(Mono.just(RefreshedResult(newAuthorizedClient, tokenResponse.id_token)))
            }
            .doOnSuccess {
                logger.info("Successfully refreshed access token for user [${authentication.name}]")
            }
            .doOnError { error ->
                logger.error("Failed to refresh access token for user [${authentication.name}]: ${error.message}")
            }
            .onErrorReturn(RefreshedResult(authorizedClient, null))
    }

    private fun buildRefreshTokenRequest(refreshToken: String): String {
        return "grant_type=refresh_token&refresh_token=$refreshToken"
    }

    /**
     * Builds a Token Exchange request asking the provider to issue an ID Token
     * based on the freshly refreshed access token.
     *
     * RFC 8693 style parameters are used here; the provider must support token exchange.
     */
    private fun buildIdTokenExchangeRequest(accessToken: String): String {
        val grantType = "urn:ietf:params:oauth:grant-type:token-exchange"
        val subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
        val requestedTokenType = "urn:ietf:params:oauth:token-type:id_token"
        return "grant_type=$grantType&subject_token=$accessToken&subject_token_type=$subjectTokenType&requested_token_type=$requestedTokenType"
    }

    data class TokenResponse(
        val access_token: String,
        val token_type: String? = "Bearer",
        val expires_in: Long? = 3600,
        val refresh_token: String? = null,
        val scope: String? = null,
        val id_token: String? = null
    )

    data class RefreshedResult(
        val authorizedClient: OAuth2AuthorizedClient,
        val idToken: String?
    )
}

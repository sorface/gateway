package by.sorface.gateway.config

import org.springframework.http.MediaType
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.util.Assert
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.net.URI

class OidcBackChannelServerLogoutSuccessHandler(
    private val clientRegistrationRepository: ReactiveClientRegistrationRepository
) : ServerLogoutSuccessHandler {

    private val webClient: WebClient = WebClient.create();

    private val serverLogoutSuccessHandler = RedirectServerLogoutSuccessHandler()

    private var postLogoutRedirectUri: String? = null

    override fun onLogoutSuccess(exchange: WebFilterExchange, authentication: Authentication): Mono<Void> {
        // @formatter:off
        return Mono.just(authentication)
            .filter{ auth -> OAuth2AuthenticationToken::class.java.isInstance(auth)}
            .filter{ auth -> auth.principal is OidcUser}
            .map{obj: Authentication? -> OAuth2AuthenticationToken::class.java.cast(obj)}
            .map{obj: OAuth2AuthenticationToken -> obj.authorizedClientRegistrationId}
            .flatMap{registrationId: String? -> clientRegistrationRepository.findByRegistrationId(registrationId)}
            .flatMap{ clientRegistration: ClientRegistration ->
                val endSessionEndpoint = endSessionEndpoint(clientRegistration) ?: return@flatMap Mono.empty<String>()
                val idToken = idToken(authentication)

                val postLogoutRedirectUri = postLogoutRedirectUri(exchange.exchange.request, clientRegistration)

                val formData = LinkedMultiValueMap<String, String>().apply {
                    add("id_token_hint", idToken)
                    add("post_logout_redirect_uri", postLogoutRedirectUri)
                }

                return@flatMap webClient.post()
                    .uri(endSessionEndpoint)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(formData))
                    .exchangeToMono { Mono.empty() }
            }
            .switchIfEmpty(
                serverLogoutSuccessHandler.onLogoutSuccess(exchange, authentication).then(Mono.empty())
            )
            .then()
    }

    private fun endSessionEndpoint(clientRegistration: ClientRegistration?): URI? {
        if (clientRegistration != null) {
            val endSessionEndpoint = clientRegistration.providerDetails
                .configurationMetadata["end_session_endpoint"]
            if (endSessionEndpoint != null) {
                return URI.create(endSessionEndpoint.toString())
            }
        }
        return null
    }

    private fun idToken(authentication: Authentication): String {
        return (authentication.principal as OidcUser).idToken.tokenValue
    }

    private fun postLogoutRedirectUri(request: ServerHttpRequest, clientRegistration: ClientRegistration): String? {
        if (this.postLogoutRedirectUri == null) {
            return null
        }
        val uriComponents = UriComponentsBuilder.fromUri(request.uri)
            .replacePath(request.path.contextPath().value())
            .replaceQuery(null)
            .fragment(null)
            .build()

        val uriVariables: MutableMap<String, String?> = HashMap()
        val scheme = uriComponents.scheme
        uriVariables["baseScheme"] = scheme ?: ""
        uriVariables["baseUrl"] = uriComponents.toUriString()

        val host = uriComponents.host
        uriVariables["baseHost"] = host ?: ""

        val path = uriComponents.path
        uriVariables["basePath"] = path ?: ""

        val port = uriComponents.port
        uriVariables["basePort"] = if (port == -1) "" else ":$port"

        uriVariables["registrationId"] = clientRegistration.registrationId

        return UriComponentsBuilder.fromUriString(postLogoutRedirectUri!!)
            .buildAndExpand(uriVariables)
            .toUriString()
    }

    fun setPostLogoutRedirectUri(postLogoutRedirectUri: String?) {
        Assert.notNull(postLogoutRedirectUri, "postLogoutRedirectUri cannot be null")
        this.postLogoutRedirectUri = postLogoutRedirectUri
    }

    fun setLogoutSuccessUrl(logoutSuccessUrl: URI?) {
        Assert.notNull(logoutSuccessUrl, "logoutSuccessUrl cannot be null")
        serverLogoutSuccessHandler.setLogoutSuccessUrl(logoutSuccessUrl)
    }

}
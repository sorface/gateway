package by.sorface.gateway.config.handler

import by.sorface.gateway.config.properties.SecurityProperties
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.user.DefaultOAuth2User
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.test.context.ActiveProfiles
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import java.net.URI

@SpringBootTest
@ActiveProfiles("test")
class OAuth2RedirectAuthenticationSuccessHandlerIntegrationTest {

    @Autowired
    private lateinit var securityProperties: SecurityProperties

    @Test
    fun `should successfully redirect to allowed host after authentication`() {
        // Given
        val redirectLocation = "http://localhost:3000/dashboard"
        val handler = OAuth2RedirectAuthenticationSuccessHandler(
            requestCache = TestServerRequestCache(redirectLocation, securityProperties.queryParamNameRedirectLocation),
            queryParamNameRedirectLocation = securityProperties.queryParamNameRedirectLocation,
            allowedHosts = setOf("localhost", "localhost:3000")
        )

        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/login/oauth2/code/passport").build()
        )

        val webFilterExchange = WebFilterExchange(exchange, { Mono.empty() })
        val authentication = createTestAuthentication()

        // When
        val result = handler.onAuthenticationSuccess(webFilterExchange, authentication)

        // Then
        StepVerifier.create(result)
            .verifyComplete()

        val location = exchange.response.headers.location
        assert(location?.toString() == redirectLocation) {
            "Expected location to be $redirectLocation but was ${location?.toString()}"
        }
    }

    @Test
    fun `should reject redirect to unauthorized host`() {
        // Given
        val unauthorizedRedirectLocation = "http://unauthorized-host.com/dashboard"
        val handler = OAuth2RedirectAuthenticationSuccessHandler(
            requestCache = TestServerRequestCache(unauthorizedRedirectLocation, securityProperties.queryParamNameRedirectLocation),
            queryParamNameRedirectLocation = securityProperties.queryParamNameRedirectLocation,
            allowedHosts = setOf("localhost", "localhost:3000")
        )

        val exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("/login/oauth2/code/passport").build()
        )

        val webFilterExchange = WebFilterExchange(exchange, { Mono.empty() })
        val authentication = createTestAuthentication()

        // When & Then
        StepVerifier.create(handler.onAuthenticationSuccess(webFilterExchange, authentication))
            .expectError(IllegalArgumentException::class.java)
            .verify()
    }

    private fun createTestAuthentication(): Authentication {
        val attributes = mapOf(
            "sub" to "test-user",
            "name" to "Test User",
            "email" to "test@example.com"
        )
        return TestOAuth2Authentication(
            DefaultOAuth2User(emptyList(), attributes, "sub")
        )
    }
}

class TestServerRequestCache(
    private val redirectLocation: String,
    private val paramName: String
) : org.springframework.security.web.server.savedrequest.ServerRequestCache {
    override fun saveRequest(exchange: org.springframework.web.server.ServerWebExchange): Mono<Void> {
        return Mono.empty()
    }

    override fun getRedirectUri(exchange: org.springframework.web.server.ServerWebExchange): Mono<URI> {
        return Mono.just(
            URI.create("/?$paramName=$redirectLocation")
        )
    }

    override fun removeMatchingRequest(exchange: org.springframework.web.server.ServerWebExchange): Mono<org.springframework.http.server.reactive.ServerHttpRequest> {
        return Mono.empty()
    }
}

class TestOAuth2Authentication(
    private val principal: DefaultOAuth2User
) : Authentication {
    override fun getName(): String = principal.name
    override fun getAuthorities() = principal.authorities
    override fun getCredentials() = null
    override fun getDetails() = null
    override fun getPrincipal() = principal
    override fun isAuthenticated() = true
    override fun setAuthenticated(isAuthenticated: Boolean) {}
} 
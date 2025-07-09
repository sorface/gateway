package by.sorface.gateway.config.handler

import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.springframework.http.HttpStatus
import org.springframework.mock.web.reactive.function.server.MockServerRequest
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import java.net.URI
import org.assertj.core.api.Assertions.assertThat
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.web.server.WebSession
import java.util.HashMap

class OAuth2RedirectAuthenticationSuccessHandlerIntegrationTest {

    private val handler = OAuth2RedirectAuthenticationSuccessHandler(
        queryParamNameRedirectLocation = "redirect-location",
        allowedHosts = setOf("localhost", "example.com")
    )

    @Test
    fun `should redirect to saved location when valid`() {
        // Given
        val redirectLocation = "http://localhost:3000/dashboard"
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build())
        
        // Mock saved request attributes
        val savedRequest = mapOf(
            "attributes" to mapOf(
                "redirect-location" to redirectLocation
            )
        )
        exchange.attributes["SPRING_SECURITY_SAVED_REQUEST"] = savedRequest

        val authentication = mock<OAuth2AuthenticationToken>()
        val principal = mock<OAuth2User>()
        whenever(authentication.name).thenReturn("test-user")
        whenever(authentication.principal).thenReturn(principal)
        whenever(principal.attributes).thenReturn(mapOf("sub" to "test-user"))

        val webFilterExchange = WebFilterExchange(exchange, mock())

        // When
        val result = handler.onAuthenticationSuccess(webFilterExchange, authentication)

        // Then
        StepVerifier.create(result)
            .verifyComplete()

        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FOUND)
        assertThat(exchange.response.headers.location).isEqualTo(URI.create(redirectLocation))
    }

    @Test
    fun `should redirect to default location when no saved request`() {
        // Given
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build())
        val authentication = mock<OAuth2AuthenticationToken>()
        val principal = mock<OAuth2User>()
        whenever(authentication.name).thenReturn("test-user")
        whenever(authentication.principal).thenReturn(principal)
        whenever(principal.attributes).thenReturn(mapOf("sub" to "test-user"))

        val webFilterExchange = WebFilterExchange(exchange, mock())

        // When
        val result = handler.onAuthenticationSuccess(webFilterExchange, authentication)

        // Then
        StepVerifier.create(result)
            .verifyComplete()

        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FOUND)
        assertThat(exchange.response.headers.location).isEqualTo(URI.create("/"))
    }

    @Test
    fun `should redirect to default location when redirect location is invalid`() {
        // Given
        val redirectLocation = "http://malicious.com/dashboard"
        val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build())
        
        // Mock saved request attributes
        val savedRequest = mapOf(
            "attributes" to mapOf(
                "redirect-location" to redirectLocation
            )
        )
        exchange.attributes["SPRING_SECURITY_SAVED_REQUEST"] = savedRequest

        val authentication = mock<OAuth2AuthenticationToken>()
        val principal = mock<OAuth2User>()
        whenever(authentication.name).thenReturn("test-user")
        whenever(authentication.principal).thenReturn(principal)
        whenever(principal.attributes).thenReturn(mapOf("sub" to "test-user"))

        val webFilterExchange = WebFilterExchange(exchange, mock())

        // When
        val result = handler.onAuthenticationSuccess(webFilterExchange, authentication)

        // Then
        StepVerifier.create(result)
            .verifyComplete()

        assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.FOUND)
        assertThat(exchange.response.headers.location).isEqualTo(URI.create("/"))
    }
} 
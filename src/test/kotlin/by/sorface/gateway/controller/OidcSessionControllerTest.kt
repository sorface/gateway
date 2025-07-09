package by.sorface.gateway.controller

import by.sorface.gateway.service.RedisReactiveOidcSessionRegistry
import org.junit.jupiter.api.Test
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.reactive.server.WebTestClient
import reactor.core.publisher.Flux
import java.time.Instant
import java.util.*

@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class OidcSessionControllerTest {

    @Autowired
    private lateinit var webTestClient: WebTestClient

    @MockBean
    private lateinit var sessionRegistry: RedisReactiveOidcSessionRegistry

    @Test
    fun `should return 401 for unauthenticated user`() {
        webTestClient.get()
            .uri("/api/v1/oidc/sessions?registrationId=passport")
            .exchange()
            .expectStatus().isUnauthorized
    }

    @Test
    fun `should return sessions for authenticated user`() {
        // Given
        val now = Instant.now()
        val idToken = createIdToken(now)
        val user = DefaultOidcUser(emptyList(), idToken)
        val authorities = mapOf(
            "registrationId" to "passport",
            "principalName" to "test-user"
        )
        val testSession = OidcSessionInformation("test-session-id", authorities, user)

        whenever(sessionRegistry.findByPrincipalName("passport", "test-user"))
            .thenReturn(Flux.just(testSession))

        // When & Then
        webTestClient
            .mutateWith(SecurityMockServerConfigurers.mockOAuth2Login()
                .attributes { it["sub"] = "test-user" })
            .get()
            .uri("/api/v1/oidc/sessions?registrationId=passport")
            .exchange()
            .expectStatus().isOk
            .expectBody()
            .jsonPath("$[0].registrationId").isEqualTo("passport")
            .jsonPath("$[0].principalName").isEqualTo("test-user")
            .jsonPath("$[0].sessionId").isEqualTo("test-session-id")
    }

    @Test
    fun `should return empty list when no sessions found`() {
        // Given
        whenever(sessionRegistry.findByPrincipalName("passport", "test-user"))
            .thenReturn(Flux.empty())

        // When & Then
        webTestClient
            .mutateWith(SecurityMockServerConfigurers.mockOAuth2Login()
                .attributes { it["sub"] = "test-user" })
            .get()
            .uri("/api/v1/oidc/sessions?registrationId=passport")
            .exchange()
            .expectStatus().isOk
            .expectBody()
            .jsonPath("$").isArray
            .jsonPath("$").isEmpty
    }

    @Test
    fun `should return 400 when registrationId is missing`() {
        webTestClient
            .mutateWith(SecurityMockServerConfigurers.mockOAuth2Login()
                .attributes { it["sub"] = "test-user" })
            .get()
            .uri("/api/v1/oidc/sessions")
            .exchange()
            .expectStatus().isBadRequest
    }

    private fun createIdToken(now: Instant): OidcIdToken {
        val claims = mapOf(
            "sub" to "test-user",
            "iat" to now.epochSecond,
            "exp" to now.plusSeconds(3600).epochSecond,
            "iss" to "https://test-issuer.com"
        )
        return OidcIdToken("token-" + UUID.randomUUID(), now, now.plusSeconds(3600), claims)
    }
} 
package by.sorface.gateway.controller

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class SessionControllerTest {

    @Autowired
    private lateinit var webTestClient: WebTestClient

    @Test
    fun `should return session info for anonymous user`() {
        webTestClient.get()
            .uri("/api/v1/sessions")
            .exchange()
            .expectStatus().isOk
            .expectBody()
            .jsonPath("$.username").isEqualTo("anonymous")
            .jsonPath("$.authenticated").isEqualTo(false)
            .jsonPath("$.authorities").isEmpty
            .jsonPath("$.createdAt").exists()
            .jsonPath("$.expiresAt").exists()
    }

    @Test
    fun `should return session info for authenticated user`() {
        webTestClient
            .mutateWith(SecurityMockServerConfigurers.mockOAuth2Login())
            .get()
            .uri("/api/v1/sessions")
            .exchange()
            .expectStatus().isOk
            .expectBody()
            .jsonPath("$.username").exists()
            .jsonPath("$.authenticated").isEqualTo(true)
            .jsonPath("$.authorities").isArray
            .jsonPath("$.createdAt").exists()
            .jsonPath("$.expiresAt").exists()
    }
} 
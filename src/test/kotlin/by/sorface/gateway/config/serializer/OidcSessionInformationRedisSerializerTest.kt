package by.sorface.gateway.config.serializer

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import java.time.Instant
import java.util.*

class OidcSessionInformationRedisSerializerTest {

    private val serializer = OidcSessionInformationRedisSerializer()

    @Test
    fun `test serialization and deserialization`() {
        // Given
        val now = Instant.now()
        val idToken = createIdToken(now)
        val user = DefaultOidcUser(emptyList(), idToken)
        val authorities = mapOf(
            "registrationId" to "testRegistration",
            "principalName" to "testUser"
        )
        val sessionInfo = OidcSessionInformation("session123", authorities, user)

        // When
        val serialized = serializer.serialize(sessionInfo)
        val deserialized = serializer.deserialize(serialized)

        // Then
        assertThat(deserialized).isNotNull
        assertThat(deserialized!!.sessionId).isEqualTo(sessionInfo.sessionId)
        assertThat(deserialized.authorities).isEqualTo(sessionInfo.authorities)
        assertThat(deserialized.principal.attributes).isEqualTo(sessionInfo.principal.attributes)
    }

    @Test
    fun `test null handling`() {
        // When
        val serialized = serializer.serialize(null)
        val deserialized = serializer.deserialize(null)

        // Then
        assertThat(serialized).isNull()
        assertThat(deserialized).isNull()
    }

    @Test
    fun `test session with minimal data`() {
        // Given
        val now = Instant.now()
        val idToken = createIdToken(now)
        val user = DefaultOidcUser(emptyList(), idToken)
        val authorities = mapOf(
            "registrationId" to "testRegistration",
            "principalName" to "testUser"
        )
        val sessionInfo = OidcSessionInformation("session123", authorities, user)

        // When
        val serialized = serializer.serialize(sessionInfo)
        val deserialized = serializer.deserialize(serialized)

        // Then
        assertThat(deserialized).isNotNull
        assertThat(deserialized!!.sessionId).isEqualTo(sessionInfo.sessionId)
        assertThat(deserialized.authorities).isEqualTo(sessionInfo.authorities)
        assertThat(deserialized.principal.attributes).isEqualTo(sessionInfo.principal.attributes)
    }

    private fun createIdToken(now: Instant): OidcIdToken {
        val claims = mapOf(
            "sub" to "testUser",
            "iat" to now.epochSecond,
            "exp" to now.plusSeconds(3600).epochSecond,
            "iss" to "https://test-issuer.com"
        )
        return OidcIdToken("token-" + UUID.randomUUID(), now, now.plusSeconds(3600), claims)
    }
} 
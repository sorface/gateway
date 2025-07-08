package by.sorface.gateway.config.serializer

import by.sorface.gateway.model.OidcSessionInformation
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Instant

class OidcSessionInformationRedisSerializerTest {

    private val serializer = OidcSessionInformationRedisSerializer()

    @Test
    fun `test serialization and deserialization`() {
        // Given
        val now = Instant.now()
        val sessionInfo = OidcSessionInformation(
            principalName = "testUser",
            sessionId = "session123",
            registrationId = "testRegistration",
            issuedAt = now,
            expiresAt = now.plusSeconds(3600)
        )

        // When
        val serialized = serializer.serialize(sessionInfo)
        val deserialized = serializer.deserialize(serialized)

        // Then
        assertThat(deserialized).isNotNull
        assertThat(deserialized!!.principalName).isEqualTo(sessionInfo.principalName)
        assertThat(deserialized.sessionId).isEqualTo(sessionInfo.sessionId)
        assertThat(deserialized.registrationId).isEqualTo(sessionInfo.registrationId)
        assertThat(deserialized.issuedAt).isEqualTo(sessionInfo.issuedAt)
        assertThat(deserialized.expiresAt).isEqualTo(sessionInfo.expiresAt)
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
    fun `test session with null timestamps`() {
        // Given
        val sessionInfo = OidcSessionInformation(
            principalName = "testUser",
            sessionId = "session123",
            registrationId = "testRegistration",
            issuedAt = null,
            expiresAt = null
        )

        // When
        val serialized = serializer.serialize(sessionInfo)
        val deserialized = serializer.deserialize(serialized)

        // Then
        assertThat(deserialized).isNotNull
        assertThat(deserialized!!.principalName).isEqualTo(sessionInfo.principalName)
        assertThat(deserialized.sessionId).isEqualTo(sessionInfo.sessionId)
        assertThat(deserialized.registrationId).isEqualTo(sessionInfo.registrationId)
        assertThat(deserialized.issuedAt).isNull()
        assertThat(deserialized.expiresAt).isNull()
    }
} 
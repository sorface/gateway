package by.sorface.gateway.model

import java.io.Serializable
import java.time.Instant

data class OidcSessionInformation(
    val principalName: String,
    val sessionId: String,
    val registrationId: String,
    val issuedAt: Instant?,
    val expiresAt: Instant?
) : Serializable 
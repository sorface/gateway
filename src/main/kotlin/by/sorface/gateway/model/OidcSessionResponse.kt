package by.sorface.gateway.model

import java.time.Instant

data class OidcSessionResponse(
    val sessionId: String,
    val registrationId: String,
    val principalName: String,
) 
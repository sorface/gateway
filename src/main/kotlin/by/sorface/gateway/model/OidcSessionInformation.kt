package by.sorface.gateway.model

import java.time.Instant

data class OidcSessionData(
    val sessionId: String,
    val registrationId: String,
    val principalName: String
) 
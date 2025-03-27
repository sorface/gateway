package by.sorface.gateway.dao.nosql.model

import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash
import java.time.Instant

@RedisHash("gateway:oauth2_authorized_client")
class OAuth2AuthorizedClientModel {

    @Id
    var id: String? = null

    var clientRegistrationId: String? = null

    var principalName: String? = null

    var accessTokenType: String? = null

    var accessTokenValue: String? = null

    var accessTokenIssuedAt: Instant? = null

    var accessTokenExpiresAt: Instant? = null

    var accessTokenScopes: String? = null

    var refreshTokenValue: String? = null

    var refreshTokenIssuedAt: Instant? = null

}
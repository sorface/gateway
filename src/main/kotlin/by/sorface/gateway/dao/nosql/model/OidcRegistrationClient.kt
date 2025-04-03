package by.sorface.gateway.dao.nosql.model

import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash
import java.io.Serializable

@RedisHash("oidc:registration:client")
class OidcRegistrationClient : Serializable {

    @Id
    var id: String? = null

    var registrationUrl: String? = null

    var registrationToken: String? = null

    var clientId: String? = null

    var clientName: String? = null

    var clientSecret: String? = null

    var clientUri: String? = null

    var redirectUris: List<String> = mutableListOf()

    var grantTypes: List<String> = mutableListOf()

    var scopes: List<String> = mutableListOf()

}
package by.sorface.gateway.config.serializer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.core.GrantedAuthority
import org.springframework.stereotype.Component
import java.time.Instant

@Component
class OidcSessionInformationRedisSerializer : RedisSerializer<OidcSessionInformation> {
    private val objectMapper = ObjectMapper().apply {
        registerModule(JavaTimeModule())
    }

    override fun serialize(info: OidcSessionInformation?): ByteArray? {
        if (info == null) return null
        
        val data = mapOf(
            "sessionId" to info.sessionId,
            "authorities" to info.authorities,
            "userClaims" to (info.principal as OidcUser).claims,
            "userAuthorities" to info.principal.authorities.map { authority: GrantedAuthority -> authority.authority }
        )
        return objectMapper.writeValueAsBytes(data)
    }

    override fun deserialize(bytes: ByteArray?): OidcSessionInformation? {
        if (bytes == null) return null
        
        val data = objectMapper.readValue(bytes, Map::class.java) as Map<String, Any>
        val sessionId = data["sessionId"] as String
        val authorities = data["authorities"] as Map<String, String>
        val userClaims = data["userClaims"] as Map<String, Any>
        
        // Create a simple OIDC ID token from claims
        val idToken = OidcIdToken(
            "dummy-token",
            userClaims["iat"]?.let { objectMapper.convertValue(it, Instant::class.java) },
            userClaims["exp"]?.let { objectMapper.convertValue(it, Instant::class.java) },
            userClaims
        )
        
        val user = DefaultOidcUser(emptyList(), idToken)
        
        return OidcSessionInformation(sessionId, authorities, user)
    }
} 
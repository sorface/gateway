package by.sorface.gateway.config.serializer

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.core.GrantedAuthority
import org.springframework.stereotype.Component
import java.time.Instant

@Component
open class OidcSessionInformationRedisSerializer : RedisSerializer<OidcSessionInformation> {
    private val objectMapper = ObjectMapper().apply {
        registerModule(JavaTimeModule())
        registerKotlinModule()
    }

    override fun serialize(info: OidcSessionInformation?): ByteArray? {
        if (info == null) return null
        
        val data = mapOf(
            "sessionId" to info.sessionId,
            "authorities" to info.authorities,
            "principal" to serializePrincipal(info.principal)
        )
        
        return objectMapper.writeValueAsBytes(data)
    }

    override fun deserialize(bytes: ByteArray?): OidcSessionInformation? {
        if (bytes == null) return null

        @Suppress("UNCHECKED_CAST")
        val data = objectMapper.readValue(bytes, Map::class.java) as Map<String, Any>
        
        val sessionId = data["sessionId"] as String
        @Suppress("UNCHECKED_CAST")
        val authorities = data["authorities"] as Map<String, String>
        @Suppress("UNCHECKED_CAST")
        val principalData = data["principal"] as Map<String, Any>
        
        val principal = deserializePrincipal(principalData)
        
        return OidcSessionInformation(sessionId, authorities, principal)
    }

    private fun serializePrincipal(principal: OidcUser): Map<String, Any> {
        return mapOf(
            "idToken" to serializeIdToken(principal.idToken),
            "attributes" to principal.attributes,
            "authorities" to principal.authorities.map { it.authority }
        )
    }

    private fun serializeIdToken(idToken: OidcIdToken): Map<String, Any> {
        val claims = idToken.claims.mapValues { (key, value) ->
            when (key) {
                "exp", "iat" -> {
                    if (value is Long) {
                        return@mapValues value
                    }

                    if (value is Instant) {
                        return@mapValues (value.epochSecond.toString() + "L")
                    }

                    return@mapValues "0L"
                }
                else -> value
            }
        }

        return mapOf(
            "tokenValue" to idToken.tokenValue,
            "issuedAt" to (idToken.issuedAt?.epochSecond?.toString() + "L" ?: "0L"),
            "expiresAt" to (idToken.expiresAt?.epochSecond?.toString() + "L" ?: "0L"),
            "claims" to claims
        )
    }

    private fun deserializePrincipal(data: Map<String, Any>): OidcUser {
        @Suppress("UNCHECKED_CAST")
        val idTokenData = data["idToken"] as Map<String, Any>
        val idToken = deserializeIdToken(idTokenData)
        
        @Suppress("UNCHECKED_CAST")
        val authorities = (data["authorities"] as List<String>).map { 
            object : GrantedAuthority {
                override fun getAuthority() = it
            }
        }
        
        return DefaultOidcUser(authorities, idToken)
    }

    private fun deserializeIdToken(data: Map<String, Any>): OidcIdToken {
        val tokenValue = data["tokenValue"] as String
        val issuedAt = (data["issuedAt"] as String).removeSuffix("L").toLong().let { Instant.ofEpochSecond(it) }
        val expiresAt = (data["expiresAt"] as String).removeSuffix("L").toLong().let { Instant.ofEpochSecond(it) }
        
        @Suppress("UNCHECKED_CAST")
        val claims = (data["claims"] as Map<String, Any>).mapValues { (key, value) ->
            when (key) {
                "exp", "iat" -> (value as String).removeSuffix("L").toLong()
                else -> value
            }
        }

        return OidcIdToken(tokenValue, issuedAt, expiresAt, claims)
    }
} 
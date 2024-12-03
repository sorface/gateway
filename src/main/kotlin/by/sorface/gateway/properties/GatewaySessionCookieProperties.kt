package by.sorface.gateway.properties

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.web.server.Cookie.SameSite

@ConfigurationProperties(prefix = "gateway.session.cookie")
data class GatewaySessionCookieProperties(

    /*Session cookie name*/
    val name: String,

    /*HTTP only session cookie*/
    val httpOnly: Boolean = false,

    /*Secure session cookie*/
    val secure: Boolean = false,

    /*Domain session cookie*/
    val domain: String,

    /*Path session cookie*/
    val path: String,

    /*SameSite session cookie*/
    val sameSite: SameSite = SameSite.LAX,

)
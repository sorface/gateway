package by.sorface.gateway.config.properties

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.bind.ConstructorBinding
import java.time.Duration

/**
 * Configuration properties for session management.
 */
@ConfigurationProperties(prefix = "spring.session")
data class SessionProperties(
    /**
     * Cookie configuration properties for the session.
     */
    val cookie: CookieProperties = CookieProperties()
) {
    /**
     * Configuration properties for session cookies.
     */
    data class CookieProperties(
        /**
         * The name of the session cookie.
         * Default value is "gtw_sid".
         */
        val name: String = "gtw_sid",
        
        /**
         * The domain of the session cookie.
         * Default value is "localhost".
         */
        val domain: String = "localhost",
        
        /**
         * The path of the session cookie.
         * Default value is "/".
         */
        val path: String = "/",
        
        /**
         * Whether the session cookie should be HTTP only.
         * Default value is true.
         */
        val httpOnly: Boolean = true,
        
        /**
         * Whether the session cookie should be secure.
         * Default value is false.
         */
        val secure: Boolean = false,
        
        /**
         * The SameSite attribute of the session cookie.
         * Default value is "Lax".
         */
        val sameSite: String = "Lax",
        
        /**
         * The maximum age of the session cookie in seconds.
         * Default value is 1000000000 seconds.
         */
        val maxAge: Duration = Duration.ofSeconds(1000000000)
    )
} 
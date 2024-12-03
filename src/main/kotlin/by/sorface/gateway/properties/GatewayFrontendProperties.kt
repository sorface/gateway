package by.sorface.gateway.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "gateway.frontend.sign-in")
data class SignInProperties(val redirectQueryParam: String)

@ConfigurationProperties(prefix = "gateway.frontend.sign-out")
data class SignOutProperties(val redirectQueryParam: String)

@ConfigurationProperties(prefix = "gateway.frontend.security")
data class SecurityWhiteList(

    /**
     * Список URLs к незащищенным ресурсам
     */
    val permitAllPatterns: List<String>

)

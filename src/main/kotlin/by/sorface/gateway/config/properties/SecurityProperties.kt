package by.sorface.gateway.config.properties

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Свойства конфигурации безопасности.
 *
 * @property allowedRedirectHosts Список разрешенных хостов для редиректа после OAuth2 аутентификации
 * @property queryParamNameRedirectLocation Имя query-параметра, содержащего URL для редиректа после OAuth2 аутентификации
 */
@ConfigurationProperties(prefix = "spring.security.oauth2")
data class SecurityProperties(
    val allowedRedirectHosts: Set<String> = setOf("localhost"),
    val queryParamNameRedirectLocation: String = "redirect-location"
) 
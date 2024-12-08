package by.sorface.gateway.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "gateway.external.passport.cookie")
class ExternalPassportCookieProperties {

    /**
     * Название cookie сервера идентификации
     */
    var name: String? = null

}
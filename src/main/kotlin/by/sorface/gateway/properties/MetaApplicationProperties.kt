package by.sorface.gateway.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "spring.application")
data class MetaApplicationProperties(val version: String)
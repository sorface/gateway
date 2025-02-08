package by.sorface.gateway.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "application.metadata")
data class ApplicationMetadata(val version: String)
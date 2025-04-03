package by.sorface.gateway.dao.nosql.model

import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash

/**
 * Модель информации о сессии OIDC, хранящейся в Redis.
 */
@RedisHash("gateway:oidc:session")
class OidcSessionInformationModel {

    /**
     * Уникальный идентификатор сессии.
     */
    @Id
    var sessionId: String? = null

    var subject: String? = null

}
package by.sorface.gateway.model

/**
 * Модель ответа об ошибке.
 * 
 * @property message Детальное описание ошибки
 * @property code Код ошибки (например, "401" для ошибок аутентификации)
 */
data class ErrorResponse(
    val message: String,
    val code: String
) 
package by.sorface.gateway.dao.nosql.model.converters

import org.springframework.core.convert.converter.Converter
import org.springframework.data.convert.WritingConverter
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation
import org.springframework.stereotype.Component
import java.io.ByteArrayOutputStream
import java.io.ObjectOutputStream

/**
 * Конвертер, преобразующий объект [OidcSessionInformation] в массив байтов.
 */
@Component
@WritingConverter
class OidcSessionBytesWritingConverter : Converter<OidcSessionInformation, ByteArray> {

    /**
     * Преобразует объект [OidcSessionInformation] в массив байтов.
     *
     * @param source объект [OidcSessionInformation], который нужно преобразовать.
     * @return массив байтов, представляющий объект [OidcSessionInformation].
     * @throws RuntimeException если возникает исключение при преобразовании.
     */
    override fun convert(source: OidcSessionInformation): ByteArray {
        try {
            ByteArrayOutputStream().use { bos ->
                ObjectOutputStream(bos).use { out ->
                    out.writeObject(source)
                    out.flush()
                    return bos.toByteArray()
                }
            }
        } catch (ex: Exception) {
            throw RuntimeException(ex)
        }
    }

}

package jabba.app.util

import com.auth0.jwt.algorithms.Algorithm

object Cipher {
    val algorithm = Algorithm.HMAC256("kakoy_ti_smesharik?")

    fun encrypt(data: String?): ByteArray =
        algorithm.sign(data?.toByteArray())
}

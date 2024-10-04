package jabba.app.util

import com.auth0.jwt.JWT
import com.auth0.jwt.interfaces.DecodedJWT
import io.javalin.security.RouteRole
import jabba.app.util.Cipher
import java.util.Date

class JwtProvider {
    fun decodeJWT(token: String): DecodedJWT = JWT.require(Cipher.algorithm).build().verify(token)

    fun createJWT(subject: String, role: RouteRole): String =
        JWT.create()
            .withIssuedAt(Date())
            .withSubject(subject)
            .withClaim("role", role.toString())
            .withExpiresAt(Date(System.currentTimeMillis() + 60 * 60 * 1000))
            .sign(Cipher.algorithm)
}

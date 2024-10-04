package jabba.app.middleware

import com.auth0.jwt.interfaces.DecodedJWT
import io.javalin.Javalin
import io.javalin.http.Context
import io.javalin.security.RouteRole
import io.javalin.http.ForbiddenResponse
import io.javalin.http.UnauthorizedResponse
import io.javalin.websocket.WsConfig
import io.javalin.websocket.WsCloseStatus
import jabba.app.util.JwtProvider
import jabba.domain.User
import jabba.domain.service.UserService
import jabba.domain.service.CasinoService
import jabba.app.AccessRole

class AuthMiddleware(private val userService: UserService, private val casinoService: CasinoService, private val jwtProvider: JwtProvider) {
    private fun resolveUser(cookie: String?): Pair<Long?, RouteRole?> {
        val token = cookie?.let {
            jwtProvider.decodeJWT(it)
        }

        val userId = getUserId(token)
        val userRole = getUserRole(token)

        return Pair(userId, userRole)
    }

    fun register(app: Javalin) {
        app.beforeMatched { ctx ->
            if (ctx.matchedPath().startsWith("/api")) {
                val (userId, userRole) = resolveUser(ctx.cookie("token"))
                ctx.attribute("userId", userId)
    
                val permittedRoles = ctx.routeRoles()
    
                if (AccessRole.ANYONE !in permittedRoles && userRole !in permittedRoles) {
                    throw ForbiddenResponse("forbidden route")
                }
            }
        }

        app.wsBefore { ws ->
            ws.onConnect { ctx ->
                try {
                    ctx.enableAutomaticPings()
                    
                    val userId = resolveUser(ctx.cookie("token")).first
                        ?: throw UnauthorizedResponse("anonymous user")

                    val user = userService.load(userId)
                        ?: throw UnauthorizedResponse("user not found")

                    if (user.sessions > 1) {
                        throw ForbiddenResponse("too many sessions")
                    }

                    val results = casinoService.getResults(user.id)

                    ctx.attribute("userId", user.id)
                    ctx.attribute("results", results)
                    ctx.attribute("balance", user.balance)

                    userService.openSession(user)
                } catch (ex: Exception) {
                    ctx.closeSession(WsCloseStatus.SERVER_ERROR, ex.toString())
                    ctx.session.disconnect()
                }
            }
        }
    }

    private fun getUserId(token: DecodedJWT?): Long? {
        return token?.subject?.toLongOrNull()
    }

    private fun getUserRole(token: DecodedJWT?): RouteRole? {
        val role = token?.getClaim("role")?.asString()
            ?: return null

        return AccessRole.values().firstOrNull { it.name == role }
    }
}

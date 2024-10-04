package jabba.app.controller

import io.javalin.http.Context
import io.javalin.http.NotFoundResponse
import io.javalin.http.UnauthorizedResponse
import io.javalin.http.BadRequestResponse
import jabba.domain.User
import jabba.domain.service.UserService
import jabba.app.util.JwtProvider
import jabba.app.AccessRole

class UserController(private val userService: UserService, private val jwtProvider: JwtProvider) {
    fun register(ctx: Context) {
        val user = userService.new()

        generateJwtToken(user).apply { 
            ctx.cookie("token", this)
        }

        ctx.json({})
    }

    fun logout(ctx: Context) {
        ctx.cookie("token", "")
        ctx.json({})
    }

    fun getBalance(ctx: Context) {
        val userId = ctx.attribute<Long>("userId")
            ?: throw UnauthorizedResponse("anonymous user")

        val user = userService.load(userId)
            ?: throw NotFoundResponse("user not found")

        ctx.json(user.balance)
    }

    fun getFlag(ctx: Context) {
        val userId = ctx.attribute<Long>("userId")
            ?: throw UnauthorizedResponse("anonymous user")

        val user = userService.load(userId)
            ?: throw NotFoundResponse("user not found")

        if (user.balance < 10) {
            throw BadRequestResponse("not enough coins")
        }

        ctx.json(System.getenv("FLAG") ?: "flag{example_flag}")
    }

    private fun generateJwtToken(user: User): String {
        return jwtProvider.createJWT(user.id.toString(), AccessRole.AUTHENTICATED)
    }
}

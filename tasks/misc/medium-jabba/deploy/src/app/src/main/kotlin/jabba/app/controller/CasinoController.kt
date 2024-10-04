package jabba.app.controller

import io.javalin.http.Context
import io.javalin.http.NotFoundResponse
import io.javalin.http.BadRequestResponse
import io.javalin.http.UnauthorizedResponse
import io.javalin.websocket.WsContext
import io.javalin.websocket.WsMessageContext
import io.javalin.websocket.WsConfig
import jabba.domain.User
import jabba.domain.Guess
import jabba.domain.service.UserService
import jabba.domain.service.CasinoService
import kotlin.collections.MutableIterator

class CasinoController(private val casinoService: CasinoService, private val userService: UserService) {
    fun getResults(ws: WsConfig) {
        fun finalize(ctx: WsContext) {
            ctx.closeSession()
            ctx.session.disconnect()

            val userId = ctx.attribute<Long>("userId") ?: return
            val balance = ctx.attribute<Long>("balance") ?: 0

            userService.load(userId)?.let {
                userService.updateBalance(it, balance)
                userService.closeSession(it)
            }
        }

        fun updateBalance(ctx: WsMessageContext) {
            var balance = ctx.attribute<Long>("balance")
                ?: throw NotFoundResponse("balance not found")

            val results = ctx.attribute<MutableIterator<Guess>>("results")
                ?: throw NotFoundResponse("results not found")

            var count = ctx.message().toIntOrNull()
                ?: throw BadRequestResponse("invalid `count` value")

            var wins = 0L
            var losses = 0L

            while (count > 0 && results.hasNext()) {
                if (results.next() == Guess.Win) {
                    wins += 1
                } else {
                    losses += 1
                }

                count -= 1
                results.remove()
            }

            balance += wins - losses
            ctx.attribute("balance", balance)

            ctx.send("wins: ${wins}, losses: ${losses}, new balance: ${balance}")
        }

        ws.onMessage { ctx ->
            try {
                updateBalance(ctx)
            } catch (ex: Exception) {
                finalize(ctx)
            }
        }

        ws.onClose { ctx ->
            finalize(ctx)
        }

        ws.onError { ctx ->
            finalize(ctx)
        }
    }

    fun initialize(ctx: Context) {
        val userId = ctx.attribute<Long>("userId")
            ?: throw UnauthorizedResponse("anonymous user")

        casinoService.initialize(userId).apply {
            ctx.json(this)
        }
    }

    fun makeGuess(ctx: Context) {
        val userId = ctx.attribute<Long>("userId")
            ?: throw UnauthorizedResponse("anonymous user")

        val count = ctx.body().toIntOrNull()
            ?: throw BadRequestResponse("invalid `count` value")
    
        casinoService.makeGuesses(userId, count).apply {
            ctx.json({})
        }
    }
}

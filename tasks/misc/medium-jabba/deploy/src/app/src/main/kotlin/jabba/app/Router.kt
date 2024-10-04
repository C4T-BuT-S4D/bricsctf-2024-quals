package jabba.app

import io.javalin.Javalin
import jabba.app.AccessRole
import jabba.app.controller.UserController
import jabba.app.controller.CasinoController
import org.koin.core.component.KoinComponent

class Router(
    private val userController: UserController,
    private val casinoController: CasinoController,
) : KoinComponent {
    fun register(app: Javalin) {
        app.post("/api/user/register", userController::register, AccessRole.ANYONE)
        app.post("/api/user/logout", userController::logout, AccessRole.AUTHENTICATED)
        app.get("/api/user/balance", userController::getBalance, AccessRole.AUTHENTICATED)
        app.get("/api/user/flag", userController::getFlag, AccessRole.AUTHENTICATED)

        app.post("/api/casino/initialize", casinoController::initialize, AccessRole.AUTHENTICATED)
        app.post("/api/casino/guess", casinoController::makeGuess, AccessRole.AUTHENTICATED)
        app.ws("/api/casino/results", casinoController::getResults, AccessRole.ANYONE)
    }
}

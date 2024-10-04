package jabba.config

import jabba.domain.repository.UserRepository
import jabba.domain.service.UserService
import jabba.domain.service.CasinoService
import jabba.app.Router
import jabba.app.util.JwtProvider
import jabba.app.controller.UserController
import jabba.app.controller.CasinoController
import jabba.app.middleware.AuthMiddleware
import org.koin.dsl.module

internal object ModulesConfig {
    private val configModule = module {
        single { AppConfig() }
        single { DbConfig("jdbc:h2:mem:api", "", "").getDataSource() }
    }
    private val appModule = module {
        single { Router(get(), get()) }
        single { AuthMiddleware(get(), get(), get()) }
        single { JwtProvider() }
    }
    private val userModule = module {
        single { UserController(get(), get()) }
        single { UserService(get()) }
        single { UserRepository(get()) }
    }
    private val casinoModule = module {
        single { CasinoService() }
        single { CasinoController(get(), get()) }
    }
    internal val allModules = listOf(
        configModule,
        appModule,
        userModule,
        casinoModule,
    )
}

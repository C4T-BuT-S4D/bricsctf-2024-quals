package jabba.config

import com.fasterxml.jackson.databind.SerializationFeature
import io.javalin.Javalin
import io.javalin.json.JavalinJackson
import io.javalin.http.staticfiles.Location
import jabba.config.ModulesConfig
import jabba.app.ErrorHandler
import jabba.app.Router
import jabba.app.middleware.AuthMiddleware
import org.eclipse.jetty.server.Server
import org.koin.core.component.KoinComponent
import org.koin.core.context.GlobalContext
import org.koin.core.component.inject
import java.text.SimpleDateFormat

class AppConfig : KoinComponent {
    private val authMiddleware: AuthMiddleware by inject()
    private val router: Router by inject()

    fun setup(): Javalin {
        GlobalContext.startKoin {
            modules(ModulesConfig.allModules)
        }
        this.configureMapper()
        val app = Javalin.create { config ->
            config.apply {
                http.strictContentTypes = true
                jetty.defaultHost = "0.0.0.0"
                jetty.defaultPort = 7070
                router.contextPath = "/"
                router.ignoreTrailingSlashes = true
                router.treatMultipleSlashesAsSingleSlash = true
                staticFiles.add("/public", Location.CLASSPATH)
            }
        }.events {
            it.serverStopping {
                GlobalContext.stopKoin()
            }
        }
        authMiddleware.register(app)
        router.register(app)
        ErrorHandler.register(app)
        return app
    }

    private fun configureMapper() {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        JavalinJackson.defaultMapper()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .setDateFormat(dateFormat)
                .configure(SerializationFeature.WRITE_DATES_WITH_ZONE_ID, true)
    }
}

package jabba

import org.h2.tools.Server
import jabba.config.AppConfig

fun main() {
    Server.createWebServer().start()
    AppConfig().setup().start()
}

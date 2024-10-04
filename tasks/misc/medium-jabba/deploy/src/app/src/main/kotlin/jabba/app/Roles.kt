package jabba.app

import io.javalin.security.RouteRole

internal enum class AccessRole : RouteRole {
    ANYONE,
    AUTHENTICATED,
}

package jabba.app

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import io.javalin.Javalin
import io.javalin.websocket.WsCloseStatus
import org.eclipse.jetty.http.HttpStatus
import org.slf4j.LoggerFactory

@JsonIgnoreProperties(ignoreUnknown = true)
internal data class ErrorResponseMessage(
    val message: String
)

internal data class ErrorResponse(
    val error: String,
    @JsonProperty("REQUEST_BODY")
    val internalErrors: List<ErrorResponseMessage> = emptyList()
) {
    val allErrors = (error) + internalErrors.map { it.message }
}

object ErrorHandler {
    private val LOG = LoggerFactory.getLogger(ErrorHandler::class.java)

    fun register(app: Javalin) {
        app.exception(Exception::class.java) { e, ctx ->
            LOG.error("Exception occurred for http req -> ${ctx.url()}", e)
            val error = ErrorResponse(e.message ?: "unknown error")
            ctx.json(error).status(HttpStatus.INTERNAL_SERVER_ERROR_500)
        }
        app.wsException(Exception::class.java) { e, ctx ->
            LOG.error("Exception occurred for websocket req -> ${ctx.queryString()}", e)
            val error = ErrorResponse(e.message ?: "unknown error")
            ctx.closeSession(WsCloseStatus.SERVER_ERROR, error.toString())
        }
    }
}

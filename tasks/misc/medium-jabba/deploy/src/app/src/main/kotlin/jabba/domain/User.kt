package jabba.domain

data class User(
    val id: Long,
    val balance: Long,
    val sessions: Long,
)

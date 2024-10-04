package jabba.domain.repository

import org.jetbrains.exposed.dao.id.LongIdTable
import org.jetbrains.exposed.sql.Column
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.insertAndGetId
import org.jetbrains.exposed.sql.update
import org.jetbrains.exposed.sql.select
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
import javax.sql.DataSource
import jabba.domain.User

private object Users : LongIdTable() {
    val balance: Column<Long> = long("balance")
    val sessions: Column<Long> = long("sessions") 

    fun toDomain(row: ResultRow): User {
        return User(
            id = row[Users.id].value,
            balance = row[Users.balance],
            sessions = row[Users.sessions],
        )
    }
}

class UserRepository(private val dataSource: DataSource) {
    init {
        transaction(Database.connect(dataSource)) {
            SchemaUtils.create(Users)
        }
    }

    fun get(userId: Long): User? {
        return transaction(Database.connect(dataSource)) {
            Users.select(Users.id, Users.balance, Users.sessions)
                .where({ Users.id eq userId })
                .map { Users.toDomain(it) }
                .firstOrNull()
        }
    }

    fun create(): User {
        val id = transaction(Database.connect(dataSource)) {
            Users.insertAndGetId() { row ->
                row[Users.balance] = 0
                row[Users.sessions] = 0
            }.value
        }

        return User(id, 0, 0)
    }

    fun update(userId: Long, user: User) {
        return transaction(Database.connect(dataSource)) {
            Users.update(where = { Users.id eq userId }) { row ->
                row[Users.balance] = user.balance
                row[Users.sessions] = user.sessions
            }
        }
    }
}

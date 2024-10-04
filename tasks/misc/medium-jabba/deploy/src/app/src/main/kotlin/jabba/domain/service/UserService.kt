package jabba.domain.service

import jabba.domain.User
import jabba.domain.repository.UserRepository

class UserService(private val userRepository: UserRepository) {
    fun new(): User {
        return userRepository.create()
    }

    fun load(userId: Long): User? {
        return userRepository.get(userId)
    }

    fun updateBalance(user: User, balance: Long) {
        userRepository.update(user.id, user.copy(balance = balance))
    }

    fun openSession(user: User) {
        userRepository.get(user.id)?.let {
            userRepository.update(it.id, it.copy(sessions = it.sessions + 1))
        }
    }

    fun closeSession(user: User) {
        userRepository.get(user.id)?.let {
            userRepository.update(it.id, it.copy(sessions = it.sessions - 1))
        }
    }
}

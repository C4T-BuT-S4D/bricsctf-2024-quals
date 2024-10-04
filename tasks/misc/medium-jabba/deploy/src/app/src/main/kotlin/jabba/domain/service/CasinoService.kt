package jabba.domain.service

import jabba.domain.Guess
import jabba.domain.Casino
import kotlin.random.Random
import kotlin.collections.ArrayDeque
import kotlin.collections.MutableIterator
import java.util.concurrent.ConcurrentHashMap

class CasinoService {
    private val mapping = ConcurrentHashMap<Long, Casino>()

    fun initialize(userId: Long): Long {
        if (mapping.containsKey(userId)) {
            throw Exception("casino already initialized")
        }

        val seed = Random.nextLong()

        val random = Random(seed)
        val guesses = ArrayDeque<Guess>()

        mapping.set(userId, Casino(random, guesses))

        return seed
    }

    fun makeGuesses(userId: Long, count: Int) {
        val casino = mapping.get(userId)
            ?: throw Exception("casino isn't initialized")

        for (i in 0 .. count - 1) {
            var guess: Guess

            if (casino.random.nextDouble() < 0.05) {
                guess = Guess.Win
            } else {
                guess = Guess.Loss
            }

            casino.guesses.addLast(guess)
        }
    }

    fun getResults(userId: Long): MutableIterator<Guess> {
        val casino = mapping.get(userId)
            ?: throw Exception("casino isn't initialized")

        return casino.guesses.iterator()
    }
}

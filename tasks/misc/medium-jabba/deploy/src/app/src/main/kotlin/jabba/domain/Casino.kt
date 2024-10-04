package jabba.domain

import kotlin.random.Random
import kotlin.collections.MutableList

enum class Guess {
    Win,
    Loss,
}

data class Casino (
    val random: Random,
    val guesses: MutableList<Guess>,
)

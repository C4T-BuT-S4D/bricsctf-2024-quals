package seed

import kotlin.random.Random

enum class Guess {
    Win,
    Loss,
}

fun main(args: Array<String>) {
    val seed = args[0].toLong()

    val start = args[1].toLong()
    val count = args[2].toLong()

    val random = Random(seed)

    if (start > 0) {
        for (i in 0 .. start - 1) {
            random.nextDouble()
        }
    }

    for (i in 0 .. count - 1) {
        var guess: Guess

        if (random.nextDouble() < 0.05) {
            guess = Guess.Win
        } else {
            guess = Guess.Loss
        }

        println(guess)
    }
}

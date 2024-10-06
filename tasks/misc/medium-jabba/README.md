# BRICS+ CTF 2024 | jabba

## Description

> Attention!
> 
> Melange harvesting on Tatooine is strictly prohibited.
> 
> Thank you for your attention!

## Public archive

- [public/jabba.tar.gz](public/jabba.tar.gz)

## Deploy

```
cd deploy && docker compose up --build -d
```

## Solution

We need to find a way to skip `Guess.Loss` and consume only `Guess.Win`.

The intended solution exploits the iternal property of `ArrayList`. When the `Iterator` tries to retrieve the next object it compares the modifications couns using the following function.

[java/util/ArrayList.java#L1094](https://github.com/openjdk/jdk/blob/260d4658aefe370d8994574c20057de07fd6f197/src/java.base/share/classes/java/util/ArrayList.java#L1094)

```java
private void checkForComodification() {
    if (modCount != expectedModCount)
        throw new ConcurrentModificationException();
}
```

But variables `modCount` and `expectedModCount` have int32 type. So if we make `INT.MAX_VALUE` operations then `modCount` will overflow and the check will be passed.

So we need to create one iterator to consume successful guesses, let's call it `success_iterator`. If the next guess is `Guess.Win` then we consume it using `success_iterator`. Otherwise we create another iterator and consume `Guess.Loss`, then close the iterator and update the balance. Then synchronize the internal `modCount` of `success_iterator` with `ArrayList`.

Example solver: [solution/solver.py](solution/solver.py)

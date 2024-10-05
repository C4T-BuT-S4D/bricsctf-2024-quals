#!/usr/bin/env sage

from sage.all import *
import random
import itertools
import os

def add_noise(A):
    theta_x = RR(uniform(-pi, pi))
    Rx = matrix(RR, [[1, 0, 0], [0, cos(theta_x), -sin(theta_x)], [0, sin(theta_x), cos(theta_x)]])
    A = Rx * A

    theta_y = (theta_x^2 + 2*theta_x + 2) % RR(pi)
    Ry = matrix(RR, [[cos(theta_y), 0, sin(theta_y)], [0, 1, 0], [-sin(theta_y), 0, cos(theta_y)]])
    A = A * Ry

    theta_z = (theta_y^3 + 3*theta_y^2 + theta_y + 3) % RR(pi)
    Rz = matrix(RR, [[cos(theta_z), -sin(theta_z), 0], [sin(theta_z), cos(theta_z), 0], [0, 0, 1]])
    A = Rz * A
    return A


ctr = 60
secrets = [RR(uniform(-2,2)) for i in range(ctr)]

ResultField = RealField(40)

perm = list(itertools.permutations(range(3), int(2)))

for secret_index in range(ctr):
    # print(secrets[secret_index])
    A = random_matrix(RR, 3, 3)
    idx = random.choice(perm)

    A[idx[0], idx[1]] = 100+secret_index
    print(dumps(A).hex())
    A[idx[0], idx[1]] = secrets[secret_index]

    B = add_noise(A)
    print(dumps(B).hex())

    guess_secret = ResultField(input(f'Your guess: '))
    assert str(ResultField(secrets[secret_index])) == str(guess_secret)

print(os.getenv('FLAG', 'flag{test_test_test}'))

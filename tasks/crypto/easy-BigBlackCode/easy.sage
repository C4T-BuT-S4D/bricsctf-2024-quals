from sage.all import *
import random
import itertools

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

def generate_random_perm(perms, k):
    perm = random.choices(perms, k = int(k))
    while len(set(perm)) != k:
        perm = random.choices(perms, k = int(k))
    return perm

ctr = 10
secrets = [RR(uniform(-2,2)) for i in range(ctr)]

As = []
Bs = []
vs = []
degree = 1
perm = list(itertools.permutations(range(3), int(2)))
for secret_index in range(ctr):
    A = random_matrix(RR, 3, 3)
    idxses = generate_random_perm(list(itertools.permutations(range(3), int(2))), degree)
    variables = [secret_index, ] # generate_random_perm(list(range(ctr)), degree)
    idx = random.choice(perm)
    A[idx[0], idx[1]] = 100+secret_index

    As.append(matrix(RR, list(A)))
    vs.append(variables)

    for i, v in zip(idxses, variables):
        A[i[0], i[1]] = secrets[v]

    B = add_noise(A)

    Bs.append(B)

ResultField = RealField(40)
secrets_result = [ResultField(i) for i in secrets]

## SOLUTION PART

R = RealField(1000)

T = PolynomialRing(R, "x", ctr)
gens = T.gens()
eqs = []
for i in range(ctr):
    A = As[i].change_ring(T)
    for y in range(3):
        for x in range(3):
            if A[y, x] >= 100:
                A[y, x] = gens[int(A[y,x]-100)]
    eq = A.det()-Bs[i].change_ring(T).det()
    eqs.append(eq)

def solve_linear(eq):
    monoms = list(eq)
    return -monoms[1][0]/monoms[0][0]

sols = [ResultField(solve_linear(eq)) for eq in eqs]

sols == secrets_result
# sols = Ideal(eqs).variety() does not work with RR lol

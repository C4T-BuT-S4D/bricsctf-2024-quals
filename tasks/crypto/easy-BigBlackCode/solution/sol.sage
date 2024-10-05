from sage.all import *
import pwn

pwn.context.log_level='debug'
io = pwn.remote('127.0.0.1', 13312)

R = RealField(1000)
T.<x> = PolynomialRing(R)

ResultField = RealField(40)

# sols = Ideal(eqs).variety() does not work with RR lol
def solve_linear(eq):
    monoms = list(eq)
    return -monoms[0]/monoms[1]

ctr = 60
for __ in range(ctr):
    A = loads(bytes.fromhex(io.recvline().decode()))
    B = loads(bytes.fromhex(io.recvline().decode()))

    A = A.change_ring(T)
    B = B.change_ring(T)

    for i in range(3):
        for j in range(3):
            if A[i, j] >= 100:
                A[i, j] = x

    eq = A.det() - B.det()
    res = solve_linear(eq)
    io.sendlineafter('Your guess: ', str(ResultField(res)))

print(io.recv())

io.close()

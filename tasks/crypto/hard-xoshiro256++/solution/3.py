from sage.all import *
from sage.coding.information_set_decoder import LeeBrickellISDAlgorithm
import sys
lhs = []
rhs = []
for l in open(sys.argv[1],'r'):
    L, R = l.split()
    lhs.append(vector(GF(2), L))
    rhs.append(int(R))
lhs = matrix(GF(2), lhs)
rhs = vector(GF(2), rhs)
c = codes.LinearCode(lhs.T)
dec = LeeBrickellISDAlgorithm(c, (0, 13))
print(dec.time_estimate(), file=sys.stderr)
sol = dec.decode(rhs)
rr = lhs.solve_right(sol)
print(''.join(map(str, rr)))
print(''.join(map(str, sol - rhs)))
#print(len(rr), rr)
#print(lhs.solve_right(rhs))
#exit()
#print(''.join(map(str, dec.decode(rhs))))
exit()
for i in range(300):
    print(i)
    lhs = matrix(GF(2), lhs0)
    rhs = vector(GF(2), rhs0)
    rhs[i] += 1
    #sol = lhs.solve_right(rhs+vector(GF(2),[1]*302))
    try:
        sol = lhs.solve_right(rhs)
    #sol = lhs.solve_left(rhs)
        print(i, sol)
    except ValueError:
        pass
    #print(lhs.rank())
    #print(lhs.left_kernel().dimension())

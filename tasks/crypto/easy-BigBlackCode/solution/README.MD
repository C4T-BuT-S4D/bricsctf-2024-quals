## Intended Solution
You have matrices `A` and `B`
$$
A = \begin{bmatrix}
1 & 2 & 3\\
4 & 5 & 6\\
7 & x & 9 
\end{bmatrix}
$$
Where `x` position choices randomly
$$
B = R_{z}(\gamma)\times R_{x}(\alpha)\times A\times R_{y}(\beta)
$$
Where `R` - is [rotation matrix](https://en.wikipedia.org/wiki/Rotation_matrix).
Now you need to recover `x`.

Since $\det(R)=1$ and $\det(XY)=\det(X)\det(Y)$ 
we have $\det(B)=\det(A)=ax+b$ where we know $a,b,\det(B)$. Then $x = \frac{\\det(B)-b}{a}$
Only problem we have - sage can't solve it in `RR` correctly (because of precision) with `Ideal(eq).variety`. Then we change ring to `RealField` with bigger precision and solve it by hands:

```python
A = ...
B = ...
ResultField = RealField(40)

def solve_linear(eq):
    monoms = list(eq)
    return -monoms[0]/monoms[1]

R = RealField(1000)
T.<x> = PolynomialRing(R)

A = A.change_ring(T)
B = B.change_ring(T)
eq = A.det() - B.det()
res = solve_linear(eq)

print(str(ResultField(res)))
```
from Crypto.Util.number import getPrime, bytes_to_long
import random

flag = 'hiCTF{***}'

def lcg(a, b, x, N):
    return (a*x + b) % N

def gen_params(sz, n, s):

    p, q = getPrime(sz), getPrime(sz)
    N = p * q

    r = random.randint(1, N)
    Rs = [r]
    
    e = random.randint(1, N)

    a, b = random.randint(1, N), random.randint(1, N)
    for _ in range(n - 1):
        Rs.append(lcg(a, b, Rs[-1], N))

    Cs = [random.randint(1, N) for _ in range(n)]

    Zs = [ri*pow(s, ci, N) for ri, ci in zip(Rs, Cs)]
    
    Ts = [pow(ri, e, N) for ri in Rs]

    return a, b, e, N, Zs, Cs, Rs, Ts

a, b, e, N, Zs, Cs, Rs, Ts = gen_params(1024, 100, bytes_to_long(flag.encode()))

print(a, b, N, Zs, Cs, Ts)

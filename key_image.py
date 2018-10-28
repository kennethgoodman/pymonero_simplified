from utils import *

priv_key, pub_key = gen_keypair()

def point_to_random_point(point):
	x = sha(point)
	return x * G

key_image = point_to_random_point(pub_key)
c_s = None
r_i = gen_random_secret() - c_s * priv_key


Bob_PK = (A,B)
r = gen_random_secret()
R = r * G
d = sha(r * A) * G + B, R
P_prime = sha(a * R) * G + B = sha(a * r * G) * G + B = sha(r * A) * G + B = one_time_p
x = sha(a * R) + b
x * G = sha(a * R) * G + b * G = sha(a * R) * G + B = sha(r * A) * G + B
=> x = private_key of one_time_p
I = x * sha(P)
 



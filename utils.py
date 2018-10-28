from hashlib import sha256
from fastecdsa import curve, ecdsa, keys
import base64
ec = curve.secp256k1
G = ec.G
N = curve_order = ec.q

def sha(*args):
	key = ''.join((map(str, args))).encode()
	return int(sha256(key).hexdigest(),16)

def H_n(*args):
	key = ''.join((map(str, args))).encode()
	return int(sha256(key).hexdigest(),16) % curve_order

def H_p(*args):
	return H_n(*args) * G

def gen_random_secrets(amount=1):
	return [keys.gen_private_key(ec) for _ in range(amount)]

def gen_random_secret():
	return gen_random_secrets(1)[0]

def gen_keypair():
	priv_key, pub_key = keys.gen_keypair(ec)
	return priv_key, pub_key

def gen_keypairs(n):
	return [gen_keypair() for _ in range(n)]

def loop_around_n_from_starting(n, starting_idx):
	for index in range(n):
		new_idx = (index + starting_idx) % n
		prev_idx = (new_idx - 1) % n
		yield new_idx, prev_idx

def xor_strings(xs, ys):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))
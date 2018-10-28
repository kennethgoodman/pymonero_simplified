import numpy as np
from utils import *

def get_ring_signature(pub_keys, known_sk_i, message_to_be_signed, priv_key):
	num_in_ring = len(pub_keys)

	### set up
	random_priv_key, random_pub_key = gen_keypair()
	es = [None for _ in range(num_in_ring)]
	## set up


	## set e_j+1
	key = (known_sk_i + 1) % num_in_ring
	value = sha(str(random_pub_key) + message_to_be_signed)
	es[key] = value
	## set e_j+1
	
	secrets = gen_random_secrets(num_in_ring)
	o_secrets = copy.deepcopy(secrets)
	for current_idx, prev_idx in loop_around_n_from_starting(num_in_ring, known_sk_i + 2):
		if current_idx == known_sk_i + 1:
			break
		e = es[prev_idx]
		pk = pub_keys[prev_idx]
		s_i = secrets[prev_idx]
		value_to_be_hashed = str(s_i * G + e * pk) + message_to_be_signed
		es[current_idx] = sha(value_to_be_hashed)
	secrets[known_sk_i] = (random_priv_key - es[known_sk_i] * priv_key) % curve_order
	return (es[0], secrets)

def test_correct_setup():
	pks = [None, None, None]
	sk = None
	for i in range(3):
		priv_key, pub_key = gen_keypair()
		if i == 1:
			sk = priv_key
		pks[i] = pub_key
	M = "Hi There"
	sigma = get_ring_signature(pks, 1, M, sk)
	assert(verify_signature(sigma, pks, M))

def verify_signature(sigma, pks, message):
	e_0, secrets = sigma
	es = [e_0]
	for i in range(1, len(sigma)+1):
		new_e = sha(str(secrets[i-1] * G + es[i-1] * pks[i-1]) + message)
		es.append(new_e)
	e0 = sha(str(secrets[-1] * G + es[-1] * pks[-1]) + message)
	return e0 == es[0]

if __name__ == '__main__':
	test_correct_setup()





import numpy as np
from itertools import count, chain
from utils import *


def get_ring_of_ring_signature(rings, known_key_indexes, message_to_be_signed, priv_keys):
	scalars = k = [gen_random_secret() for _ in rings]
	secrets = s = [[gen_random_secret() for key in ring] for ring in rings]
	M = message_to_be_signed
	R_s = []
	for ring, known_key_index, i in zip(rings, known_key_indexes, count()): 
		r_i_j = k[i] * G
		for j in range(known_key_index + 1, len(ring)):
			e_i_j = sha(M, r_i_j, i, j)
			r_i_j = s[i][j] * G + e_i_j * ring[j]
		R_s.append(r_i_j)
	R_s.append(M)
	
	e0 = sha(R_s)

	for ring, known_key_index, i in zip(rings, known_key_indexes, count()): 
		e_i_j = sha(M, e0, i, 0)
		for j in range(0, known_key_index):
			r_i_j = s[i][j] * G + e_i_j * ring[j]
			e_i_j = sha(M, r_i_j, i, j+1)
		secret = priv_keys[i]
		s[i][known_key_index] = (k[i] - e_i_j * secret)
	return e0, secrets
	

def verification(sigma, rings, message):
	e0, s = sigma
	M = message
	values = []
	for i, ring in enumerate(rings):
		e_i_j = sha(M, e0, i, 0)
		for j, pubkey in enumerate(ring):
			r = s[i][j] * G + pubkey * e_i_j
			e_i_j = sha(M, r, i, j+1)
		values.append(r)
	values.append(message)
	return sha(values) == e0


def test_ring_signature():
	key_set = []
	number_of_rings = 5
	known_key_indexes = []
	known_sks = []
	for i in range(number_of_rings):
		size_of_ring = np.random.randint(2, 50)
		known_key_indexes.append(np.random.randint(size_of_ring))
		key_set.append([])
		for j in range(size_of_ring):
			priv_key, pub_key = gen_keypair()
			if j == known_key_indexes[i]:
				known_sks.append(priv_key)
			key_set[i].append(pub_key)
	message = "Hi There"
	sigma = get_ring_of_ring_signature(key_set, known_key_indexes, message, known_sks)
	assert verification(sigma, key_set, message)

if __name__ == '__main__':
	test_ring_signature()




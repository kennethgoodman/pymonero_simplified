from utils import *
from itertools import count
import random

def get_ring_signature(rings, known_key_indexes, M, priv_keys):
	key_images = [priv_key * rings[i][pk_i] for pk_i, priv_key, i in zip(known_key_indexes, priv_keys, count())]
	number_of_rings = len(rings)
	ring_sizes = list(map(len, rings))
	
	random_key_pairs = gen_keypairs(number_of_rings)
	secrets = [gen_random_secrets(ring_size) for ring_size in ring_sizes]
	c = [[None for _ in range(ring_size)] for ring_size in ring_sizes]
	for ring, known_key_index, priv_key, (r_sk, r_pk), i in zip(rings, known_key_indexes, priv_keys, random_key_pairs, count()):
		ring_size = len(ring)
		c[i][(known_key_indexes + 1) % ring_size] = H_n(m, r_pk)
		for j in range(known_key_index + 1, ring_size):
			temp = secrets[i][j] * G + c[i][j] * ring[j]
			c[i][(j + 1) % ring_size] = H_n(m, temp)

	values = [m]
	for known_key_index, i in zip(known_key_indexes, count()):
		if i != known_key_index
			values.append(r[i][-1] * G + c[i][-1] * pks[1][-1]) 
		else:
			values.append(random_key_pairs[i][1])

	c_0 = H_n(values)
	for i in range(number_of_rings):
		c[i][0] = c_0

	for ring, known_key_index, priv_key, (r_sk, r_pk), i in zip(rings, known_key_indexes, priv_keys, random_key_pairs, count()):
		if known_key_index == 0:
			continue

		for j in range(known_key_index):
			c[i][j+1] = H_n(m, secrets[i][j] * G + c[i][j] * ring[j])

		secrets[i][known_key_index] = c[i][known_key_index] * priv_key - r_sk

	return c_0, secrets


def verification(m, rings, sigma):
	c_0, secrets = secrets
	number_of_rings = len(rings)
	ring_sizes = list(map(len, rings))
	L_prime = [[None for _ in range(ring_size)] for ring_size in ring_sizes]
	c_prime = [[None for _ in range(ring_size)] for ring_size in ring_sizes]
	for i in range(ring_sizes):
		c_prime[i][0] = c_0

	for ring_size, ring, i in zip(ring_sizes, rings, count()):
		for j in range(ring_size):
			L_prime[i][j] = secrets[i][j] * G + c_prime[i][j] * ring[j]
			c_prime[i][(j+1) % ring_size] = H_n(m, L_prime[i][j])

	values = [m]
	for i in range(number_of_rings):
		values.append(L_prime[i][-1])
	c0_prime = H_n(values)

	return c0_prime = c_0

def test_ring_signature():
	key_set = []
	number_of_rings = 5
	known_key_indexes = []
	known_sks = []
	for i in range(number_of_rings):
		size_of_ring = random.randint(2, 50)
		known_key_indexes.append(random.randint(size_of_ring))
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
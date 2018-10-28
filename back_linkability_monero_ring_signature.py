from utils import *
import random

def H_n(*args):
	key = ''.join((map(str, args))).encode()
	return int(sha256(key).hexdigest(),16) % curve_order

def H_p(*args):
	return H_n(*args) * G

def get_ring_signature(pks, secret_key_index, M, sk):
	size_of_ring = len(pks)
	R = pks
	key_image = sk * H_p(pks[secret_key_index])
	random_priv_key, random_pub_key = gen_keypair()
	h_p_R = H_p(R)
	alpha_hp_r = random_priv_key * h_p_R
	c = [None for _ in range(size_of_ring)]
	c[(secret_key_index + 1) % size_of_ring] = H_n(M, random_pub_key, random_priv_key * H_p(random_pub_key))
	secrets = gen_random_secrets(size_of_ring)
	for new_idx, prev_idx in loop_around_n_from_starting(size_of_ring, secret_key_index + 2):
		if new_idx == secret_key_index + 1:
			break
		temp_1 = secrets[prev_idx] * G + c[prev_idx] * pks[prev_idx]
		temp_2 = secrets[prev_idx] * H_p(pks[prev_idx]) + c[prev_idx] * key_image
		c[new_idx] = H_n(M, temp_1, temp_2)
	secrets[secret_key_index] = random_priv_key - c[secret_key_index] * sk
	return c[0], secrets, key_image

def verification(pks, M, signature):
	c_0, secrets, key_image = signature
	size_of_ring = len(pks)
	# print(curve_order)
	# print(key_image)
	# print(curve_order * key_image)
	# if curve_order * key_image != 0:
		# return False  # make sure we are in the right subgroup?

	h_p_R = H_p(pks)
	c_prime = [None for _ in range(size_of_ring)]
	c_prime[0] = c_0
	for i in range(size_of_ring):
		temp_1 = secrets[i] * G + c_prime[i] * pks[i]
		temp_2 = secrets[i] * h_p_R + c_prime[i] * key_image
		c_prime[(i+1) % size_of_ring] = H_n(pks, key_image, M, temp_1, temp_2)

	return c_0 != c_prime[0]

def linkability(key_image, key_images):
	return key_image not in key_images


def test_one():
	message = "Hi There"
	size_of_ring = n = 8
	pks = [None for _ in range(size_of_ring)]
	secret_key_index = random.randint(0, size_of_ring - 1)
	sk = None
	for i in range(size_of_ring):
		priv_key, pub_key = gen_keypair()
		if i == secret_key_index:
			sk = priv_key
		pks[i] = pub_key
	M = "Hi There"
	sigma = get_ring_signature(pks, secret_key_index, M, sk)
	assert verification(pks, message, sigma)

def test_different_pks_same_sk():
	message = "Hi There"
	size_of_ring = n = 8
	pks = [None for _ in range(size_of_ring)]
	secret_key_index = random.randint(0, size_of_ring - 1)
	sk = None
	for i in range(size_of_ring):
		priv_key, pub_key = gen_keypair()
		if i == secret_key_index:
			sk = priv_key
		pks[i] = pub_key
	M = "Hi There"
	c_0, secrets, key_image = get_ring_signature(pks, secret_key_index, message, sk)
	assert verification(pks, message, (c_0, secrets, key_image))

	for i in range(size_of_ring):
		if i == secret_key_index:
			continue
		priv_key, pub_key = gen_keypair()
		pks[i] = pub_key
	M = "Hi There 2"
	c_02, secrets2, key_image2 = get_ring_signature(pks, secret_key_index, message, sk)
	assert verification(pks, message, (c_0, secrets, key_image))
	assert key_image2 == key_image  # Now should be different, if they are the same, someone cheated

if __name__ == '__main__':
	test_different_pks_same_sk()
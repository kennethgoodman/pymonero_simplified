from utils import *

def sign(priv_key, message):
	random_priv_key, random_pub_key = gen_keypair()
	c = sha(m, random_pub_key)
	r = random_priv_key - c * priv_key
	return (c,r)

def verification(pub_key, message, signature):
	"""
		r * G = (random_priv_key - c * priv_key) * G
			  = random_priv_key * G - c * priv_key * G
			  = random_pub_key - c * pub_key
		sha(m, random_pub_key) = c
			  = sha(m, r * G + c * pub_key)
			  = sha(m, (random_pub_key - c * pub_key) + c * pub_key) = c_prime
			  = sha(m, random_pub_key) 
	"""
	c,r = signature
	c_prime = sha(m, r * G + c * pub_key)
	return c == c_prime

if __name__ == '__main__':
	priv_key, pub_key = gen_keypair()
	message = "Hi There"
	assert(verification(pub_key, message, sign(priv_key, message)))

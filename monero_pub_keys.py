from utils import *


def generate_one_time_pub_key(pub_key_v, pub_key_s, index=0):
	r = gen_random_secret()
	return H_n(r * pub_key_v, index) * G + pub_key_s, r * G

def calcualte_kbs_prime(r_G, K_o, priv_key_v, index=0):
	temp = priv_key_v * r_G  # = r * K_v
	return K_o - H_n(temp, index) * G

def my_coins(r_G, K_o, priv_key_v, pub_key_s):
	return calcualte_kbs_prime(r_G, K_o, priv_key_v) == pub_key_s

def private_key_to_one_time_pub_key(R, priv_key_v, priv_key_s, index=0):
	return H_n(R * priv_key_v, index) + priv_key_s  # r * K_v = r * k_v * G = k_v * (r * G)

def generate_sub_address(i, priv_key_v, pub_key_v, priv_key_s, pub_key_s):
	pub_key_s_i = pub_key_s + H_n(priv_key_v, i) * G
	pub_key_v_i = priv_key_v * pub_key_s_i

	priv_key_v_i = priv_key_v * (priv_key_s + H_n(priv_key_v, i))
	priv_key_s_i = priv_key_s + H_n(priv_key_v, i)

	return (priv_key_v_i, pub_key_v_i), (priv_key_s_i, pub_key_v_i)

def test():
	(priv_key_v, pub_key_v), (priv_key_s, pub_key_s) = gen_keypairs(2)
	one_time_pub_key, R = generate_one_time_pub_key(pub_key_v, pub_key_s)
	assert my_coins(R, one_time_pub_key, priv_key_v, pub_key_s)
	assert private_key_to_one_time_pub_key(R, priv_key_v, priv_key_s) * G == one_time_pub_key

def encode_payment_id(pub_key_v, pid_tag):
	r = gen_random_secret()
	k_mask = H_n(r * pub_key_v, pid_tag)
	k_mask = str(k_mask)[:len(pid_tag)]
	return xor_strings(k_mask, pid_tag), r * G

def decode_payment_id(R, priv_key_v, pid_tag):
	k_mask = H_n(priv_key_v * R, pid_tag)
	k_mask = str(k_mask)[:len(pid_tag)]
	return xor_strings(k_mask, pid_tag)

def test_payment_id_encoding():
	(priv_key_v, pub_key_v), (priv_key_s, pub_key_s) = gen_keypairs(2)
	pid_tag = '4fdsg42gsdrsgaregefs'
	encoded, R = encode_payment_id(pub_key_v, pid_tag)
	decoded = decode_payment_id(R, priv_key_v, pid_tag)
	return decoded == pid_tag

def output_values(pub_key_v, y, r, x):
	mask = y + H_n(H_n(r * pub_key_v, t))
	amount = x + H_n(H_n(H_n(r * pub_key_v, t)))
	return mask, amount

if __name__ == '__main__':
	test()
	test_payment_id_encoding()

from utils import *
from pederson_commitments import PC, PC_Full
from AOS_RingSignature import get_ring_signature

value_want_to_represent = 54
H = gen_keypair()[1]
alpha = gen_random_secrets()[0]
pc = PC.create_commitment(H, alpha, value_want_to_represent)
binary_of_v = format(value_want_to_represent, '025b') 

k = 25  # 
secrets = gen_random_secrets(k)
secrets[-1] = alpha - sum(secrets[:-1])
pcs = []
for i, b in zip(range(k), binary_of_v[::-1]):
	p_i = PC_Full(H, secrets[i], 2**i * b)
	pcs.append(p_i)

print(sum(pcs) == pc)  # verification that they are equal

# verify that all bits of pcs are 0 or 1
# ring signature for each pcs:
ring_signatures = []
for i, (secret,b) in enumerate(zip(secrets, binary_of_v[::-1])):
	p_i = pcs[i]
	pi_minus_2i_h = p_i - 2**i * H
	known_sk_i = 0
	if b == '1':
		known_sk_i = 1
	rs = get_ring_signature([p_i], known_sk_i, "", secret)
	ring_signatures.append(rs)
print(pcs, ring_signatures)  # range proof



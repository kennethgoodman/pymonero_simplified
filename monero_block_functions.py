

def get_median_block_size(last_one_hundred_blocks):
	return median(block.block_size for block in last_one_hundred_blocks)

def M_100(last_one_hundred_blocks):
	return max(get_median_block_size(last_one_hundred_blocks), KB(300))

def max_block_size(M_100):
	return 2 * M_100

def penalty(block_size, last_one_hundred_blocks):
	M100 = M_100(last_one_hundred_blocks)
	P = B * ((block_size/M_100) - 1)**2
	B_actual = B - P
	return B_actual

def minimum_fee(block_size, last_one_hundred_blocks):
	f_b = .0004
	M100 = M_100(last_one_hundred_blocks)
	return f_b * (KB(300)/M100) * (penalty(block_size, last_one_hundred_blocks) / 10)

def block_reward(total_monero_so_far):
	L = 2**64 - 1
	M = total_monero_so_far
	tail_emission = int(0.6 * 10**12)
	return max( (L - M) >> 19, tail_emission)
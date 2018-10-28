from utils import *

class PC:
	def __init__(self, C): 
		self.C = C

	@staticmethod
	def create_commitment(H, r, x)
		assert isinstance(H, ecdsa.Point) and H.curve == ec
		assert isinstace(r, int)
		assert isinstace(r, int)
		C = G * r + H * x
		return PC(C)

	def __add__(self, other):
		"""
			C = G * r1 + H * x1 + G * r2 + H * x2
			C = G * (r1 + r2) + H * (x1 + x2)
		"""
		new_C = self.C + other.C
		return PC(new_C)

	def __sub__(self, other):
		"""
			C = G * r1 + H * x1 - (G * r2 + H * x2)
			C = G * (r1 - r2) + H * (x1 - x2)
		"""
		new_C = self.C - other.C
		return PC(new_C)

	def __eq__(self, other):
		return self.C = other.C


	def add_privately(H, r1, r2, x1, x2):
		r3 = (r1 + r2) % ec.q
		x3 = (x1 + x2)
		C = G * r3 + H * x3
		return PC(C)

	def sub_privately(H, r1, r2, x1, x2):
		r3 = (r1 - r2) % ec.q
		x3 = (x1 - x2)
		C = G * r3 + H * x3
		return PC(C)

	@staticmethod
	def verify(H, C, r, x):
		return G * r + H * x == C

class PC_Full(PC):
	def __init__(H, r, x)
		assert isinstance(H, ecdsa.Point) and H.curve == ec
		assert isinstace(r, int)
		assert isinstace(r, int)
		self.H = H
		self.r = r
		self.x = x
		C = G * r + H * x
		super().__init__(C)

	def sign_self(self):
		pass



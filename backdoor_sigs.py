from bitcoin.main import hash_to_int, fast_multiply, inv, ecdsa_raw_recover
from bitcoin.main import G, N, decode_privkey, get_privkey_format, privtopub
from bitcoin.main import encode_pubkey, ecdsa_raw_verify
from os import urandom
from hashlib import sha256
from binascii import hexlify, unhexlify
from sha3 import keccak_256 as sha3
from copy import copy

# We're going to reuse this to get duplicate R values.
# Never, ever, ever, do this with real signatures.
insecure_k = int(urandom(32).encode('hex'), 16)

# Do ECDSA signing without a random or deterministic K.
def insecure_ecdsa_sign(msghash, priv):
	global insecure_k

	z = hash_to_int(msghash)
	k = insecure_k
	r, y = fast_multiply(G, k)
	s = inv(k, N) * (z + r*decode_privkey(priv)) % N

	v, r, s = 27+((y % 2) ^ (0 if s * 2 < N else 1)), r, s if s * 2 < N else N - s
	if 'compressed' in get_privkey_format(priv):
		print("COmpressed \a")
		v += 4
	
	return v, r, s
	
# this function is from 
# https://github.com/warner/python-ecdsa/blob/master/ecdsa/numbertheory.py
def inverse_mod( a, m ):
    """Inverse of a mod m."""
    if a < 0 or m <= a: a = a % m
    # From Ferguson and Schneier, roughly:
    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod( d, c ) + ( c, )
        uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc

    # At this point, d is the GCD, and ud*a+vd*m = d.
    # If d == 1, this means that ud is a inverse.
    assert d == 1
    if ud > 0: return ud
    else: return ud + m

# Convert an int to hex.
def int_to_hex_str(i):
	h = "%0x" % i
	
	# Python truncates leading zero for some reason ...
	if len(h) % 2:
		h = "0" + h
		
	return h

# Do attack on sigs with duplicate R values.
def derivate_privkey(p, r, s1, s2, hash1, hash2):
	assert(type(p) == long)
	assert(type(r) == long)
	assert(type(s1) == long)
	assert(type(s2) == long)
	assert(type(hash1) == long)
	assert(type(hash2) == long)
	assert(len(int_to_hex_str(p)) == 64)
	assert(len(int_to_hex_str(r)) == 64)
	assert(len(int_to_hex_str(s1)) == 64)
	assert(len(int_to_hex_str(s2)) == 64)
	assert(len(int_to_hex_str(hash1)) == 64)
	assert(len(int_to_hex_str(hash2)) == 64)
	
	
	z = hash1 - hash2
	s = s1 - s2
	r_inv = inverse_mod(r, p)
	s_inv = inverse_mod(s, p)
	k = (z * s_inv) % p
	d = (r_inv * (s1 * k - hash1)) % p
	return d, k
    
# Return a hash value as an int.
def hash_as_int(hash_type, msg):
	if hash_type == "sha256":
		h = sha256(msg).hexdigest()
		
	if hash_type == "sha3":
		h = sha3(msg).hexdigest()
		
	i = int(h, 16)
	
	return i

# Gets a private key within allowed range.
def get_priv_key():
	max_priv_key = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	while 1:
		priv_key = urandom(32)
		if int(hexlify(priv_key), 16) < max_priv_key:
			return priv_key
			
# Generation solution hash to pass to Ethereum.
def gen_solution_hash(hm1, v1, r1, s1, hm2, s2, destination):
	# Create a string of hex characters with zero padding where necessary.
	
	buf = b""
	buf += int_to_hex_str(hm1)
	buf += int_to_hex_str(v1)
	buf += int_to_hex_str(r1)
	buf += int_to_hex_str(s1)
	buf += int_to_hex_str(hm2)
	buf += int_to_hex_str(s2)
	
	# Convert ethereum address to aligned hex data.
	# It's already in hex so this is easy.
	dest = destination[2:]
	if len(dest) % 2:
		dest = "0" + dest
	buf += dest
	
	# Convert hex string to bytes and hash it.
	solution_hash = sha3(unhexlify(buf)).hexdigest()
	
	# Return the solution hash as hex.
	return solution_hash

# Generate message hashes.
m1 = b"test1"
m2 = b"test2"
hm1 = hash_as_int("sha3", m1)
hm2 = hash_as_int("sha3", m2)

# Generate a key that can be retrieved.
generated = False
while generated == False:
	# Generate key pairs.
	priv_key = get_priv_key()
	pub_key = int(privtopub(priv_key).encode('hex'), 16)
	
	# Get sig components.
	v1, r1, s1 = insecure_ecdsa_sign(unhexlify(int_to_hex_str(hm1)), priv_key)
	v2, r2, s2 = insecure_ecdsa_sign(unhexlify(int_to_hex_str(hm2)), priv_key)
	
	# They should be equal for easy recovery.
	if v1 != v2:
		continue
		
	# Duplicate R is required for attack.
	if r1 != r2:
		raise Exception("Could not generate duplicate R values.")
	
	# Sig should be over unique messages.
	if s1 == s2:
		raise Exception("s1 was == s2.")
	
	# Test attack is possible.
	p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	try:
		priv_key, k = derivate_privkey(p, r1, s1, s2, hm1, hm2)
	except:
		continue

	pub_key = hexlify(privtopub(unhexlify(int_to_hex_str(priv_key))))
	
	break

# Choose an Ethereum address to redeem Ether to.
chosen_addr = raw_input("Enter an Ethereum address that can redeem the coins: [enter is default]")
if len(chosen_addr) == 0:
	# For fast testing.
	destination = "0xcfd31d218dccc9b553458f1b6c4ace40dada01f7"
else:
	destination = chosen_addr
	
# Generate a solution hash (to claim the coins without getting scammed.)
solution_hash = gen_solution_hash(hm1, v1, r1, s1, hm2, s2, destination)

# Show results.
print("Priv key = " + int_to_hex_str(priv_key))
print("Pub key = " + pub_key)
print("Address = 0x" + sha3(unhexlify(pub_key[2:])).hexdigest()[24:])
print("r1 = " + int_to_hex_str(r1))
print("s1 = " + int_to_hex_str(s1))
print("s2 = " + int_to_hex_str(s2))
print("hm1 = " + int_to_hex_str(hm1))
print("hm2 = " + int_to_hex_str(hm2))
print("v1 = " + int_to_hex_str(v1))
print("v2 = " + int_to_hex_str(v2))
print("m1 = " + m1)
print("m2 = " + m2)
print("solution hash = " + solution_hash)

print("Eth input = ")

eth_input = """ "0x%s", %d, "0x%s", "0x%s", "0x%s", "0x%s", "%s", "%s", 0""" % (int_to_hex_str(hm1), v1, int_to_hex_str(r1), int_to_hex_str(s1), int_to_hex_str(hm2), int_to_hex_str(s2), destination, destination)
print(eth_input)


rec_pub_key = ecdsa_raw_recover(unhexlify(int_to_hex_str(hm1)), (v1, r1, s1))
if v1 >= 31:
	rec_pub_key = encode_pubkey(rec_pub_key, 'hex_compressed')
else:
	rec_pub_key = encode_pubkey(rec_pub_key, 'hex')

print("Recovery 1 = " + rec_pub_key)


print("Ver sig hm1 from rec = " + str(ecdsa_raw_verify(int_to_hex_str(hm1), (v1, r1, s1), rec_pub_key)))
print("Ver sig hm1 from attack = " + str(ecdsa_raw_verify(int_to_hex_str(hm1), (v1, r1, s1), pub_key)))


rec_pub_key = ecdsa_raw_recover(unhexlify(int_to_hex_str(hm2)), (v2, r2, s2))
if v1 >= 31:
	rec_pub_key = encode_pubkey(rec_pub_key, 'hex_compressed')
else:
	rec_pub_key = encode_pubkey(rec_pub_key, 'hex')

print("Recovery 2 = " + rec_pub_key)


print("Ver sig hm2 from rec = " + str(ecdsa_raw_verify(int_to_hex_str(hm2), (v2, r2, s2), rec_pub_key)))
print("Ver sig hm2 from attack = " + str(ecdsa_raw_verify(int_to_hex_str(hm2), (v2, r2, s2), pub_key)))



#!/usr/bin/env python

import os
import ecdsa
import hashlib
import base58
import binascii
import json
import redis
import logging

# Logging
logger = logging.getLogger('brt')

## Begin Logging Setup
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
# Console Output
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)
## End Logging Setup

REDIS_HOST = os.environ.get('REDIS_HOST') or '127.0.0.1'
REDIS_PORT = os.environ.get('REDIS_PORT') or None
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD') or None
CHUNK_SIZE = os.environ.get('CHUNK_SIZE') or 1000



# def generate_wif_key(private_key):
# 	padding = b'80'
#     private_key = padding + private_key

# 	hashed_val = hashlib.sha256(binascii.hexlify(padding)).hexdigest()
# 	checksum = hashlib.sha256().hexdigest()[:8]
# 	payload = padding + checksum
# 	wif = base58.b58encode(binascii.unhexlify(payload))

# 	return wif


def generate_wallets(chunk_size=20000):
    chunk = dict()
    for i in range(chunk_size):
        private_key = os.urandom(32)
        private_key_hex = binascii.hexlify(private_key)

        # wif = generate_wif_key(private_key)

        sk = ecdsa.SigningKey.from_string(private_key, curve = ecdsa.SECP256k1)
        vk = sk.verifying_key

        public_key = b'\04' + vk.to_string()
        public_key_hex = binascii.hexlify(public_key)

        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(public_key).digest())

        network_append = b'\00' + ripemd160.digest()
        checksum = hashlib.sha256(hashlib.sha256(network_append).digest()).digest()[:4]
        binary_address = network_append + checksum

        public_address = base58.b58encode(binary_address)

        chunk[public_address.decode()] = dict(
            private_key=private_key_hex.decode(),
            # sk=sk,
            # vk=vk,
            public_key=public_key_hex.decode()
            # wif=wif,
        )

    return chunk

def found_match(public_address: str, wallet: dict, balance: int):
    logger.info(f'Found balance ({balance}) on public address {public_address}. Wallet details: {wallet}')
    r_found.hmset(public_address, wallet)
    return True

r = redis.Redis(host=REDIS_HOST, password=REDIS_PASSWORD, db=0)
r_found = redis.Redis(host=REDIS_HOST, password=REDIS_PASSWORD, db=1)

while True:
    logger.info(f'Generating {CHUNK_SIZE} wallets...')
    wallets = generate_wallets(chunk_size=CHUNK_SIZE)
    # wallets = {
    #     '3M6UcBNGZAW1HRjiFDMRcY5aXFrQ4F9E1y': {
    #         'private_key': 'd12c20802c08d85140a933224d536fd22ceac59174ac2a159bbbfd0e3ceaf2fd',
    #         'public_key': '0457c4c00b56d57cfa4f2a476d40ede96a2188297721606cfaed515ae374e34d47a8657fff018b02212dc1b0db0a6ed1d3a93c69ccdeef335d93e8a9e6df09aa2b'
    #     }
    # }

    addresses = list(wallets.keys()) #dict key is the public address
    logger.info('Querying redis...')
    response = r.mget(addresses)
    logger.info('Redis query finished')

    for idx,balance in enumerate(response):
        if balance != None:
            _ = found_match(addresses[idx], wallets[addresses[idx]], balance)

#FIXME: We need compressed addresses for all new transactions. Used compress public address for checking transactions
#FIXME: Use WIF to store private key for less bytes

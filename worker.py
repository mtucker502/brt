#!/usr/bin/env python

import os
import ecdsa
import hashlib
import base58
import binascii
import redis
import logging
import config
from time import time
import sys
from functools import wraps

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


r = redis.Redis(host=config.REDIS_HOST, password=config.REDIS_PASSWORD, db=0)
r_found = redis.Redis(host=config.REDIS_HOST, password=config.REDIS_PASSWORD, db=1)


def measure(func):
    @wraps(func)
    def _time_it(*args, **kwargs):
        start = int(round(time() * 1000))
        # start = time()
        try:
            return func(*args, **kwargs)
        finally:
            end_ = int(round(time() * 1000)) - start
            # end_ = time() - start
            logger.debug(f"{func.__name__}: {end_ if end_ > 0 else 0} ms")
    return _time_it

# def generate_wif_key(private_key):
# 	padding = b'80'
#     private_key = padding + private_key

# 	hashed_val = hashlib.sha256(binascii.hexlify(padding)).hexdigest()
# 	checksum = hashlib.sha256().hexdigest()[:8]
# 	payload = padding + checksum
# 	wif = base58.b58encode(binascii.unhexlify(payload))

# 	return wif

@measure
def generate_wallets(chunk_size=20000):
    logger.info(f'Generating {config.CHUNK_SIZE} wallets...')
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

@measure
def query_redis(r, addresses):
    logger.info('Querying redis...')
    response = r.mget(addresses)
    logger.info('Redis query finished')

    return response

@measure
def work():
        wallets = generate_wallets(chunk_size=config.CHUNK_SIZE)

        addresses = list(wallets.keys()) #dict key is the public address
        
        response = query_redis(r, addresses)
        
        for idx,balance in enumerate(response):
            if balance != None:
                _ = found_match(addresses[idx], wallets[addresses[idx]], balance)

def main():
    while True:
        work()

if __name__ == '__main__':
    if '-v' in sys.argv:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    main()

#FIXME: We need compressed addresses for all new transactions. Used compress public address for checking transactions
#FIXME: Use WIF to store private key for less bytes

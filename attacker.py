import os, utils, random

from Crypto.Cipher import AES
from typing import Dict, List, Tuple
from client_server import WUP, Client, Server

class Attacker(Client):
    def __init__(self):
        super(Attacker, self).__init__()

    def hack(self, public_key: Tuple[int, int], 
                   request: List[Tuple], 
                   server: Server
    ) -> int:
        """
        record a victim user's history request, try to 
        recover the AES key of that session of request.
        """
        # C: the encryted AES key that we want to hack
        victim_id, C, _ = request[0]
        n, e = public_key

        k_b = 0
        for b in range(127, -1, -1):
            C_b = [C[0] * ((1 << b*e) % n) % n]

            aes_key = utils.bit_mask(128) & (k_b << b)
            aes = AES.new(aes_key.to_bytes(16, 'big'))

            wups = WUP("I want to hack your aes key", self.mac, self.imei)
            encrypted_wups = [aes.encrypt(wup) for wup in wups]

            req = [(victim_id, C_b, wup) for wup in encrypted_wups]

            k_b = (1-server.process_request(req)) << (127-b) | k_b

        # use the hacked AES key to encrypt another plain text
        victim_aes = k_b

        aes = AES.new(victim_aes.to_bytes(16, 'big'))

        wups = WUP("I hacked your aes key successfully", self.mac, self.imei)
        encrypted_wups = [aes.encrypt(wup) for wup in wups]

        req = [(victim_id, C, wup) for wup in encrypted_wups]
        assert server.process_request(req) == True, "hack failed"

        return victim_aes


def test_hack():
    user1 = Client()
    req1 = user1.send_request("wei cheng yong xiao is a good man.")

    server = Server()
    server.register(user1)

    attacker = Attacker()
    attacker.hack(user1.rsa.public_key, req1, server)

test_hack()

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
            # assume that the encode way is naive encoding
            # according to the fundamental property of multiplication
            # in modular arithmetic, we should compute C_b for each
            # block of this data.
            C_b = [c * ((1 << b*e) % n) % n for c in C]

            # after leftshift, the aes key will be longer than 128 bit.
            # recall that the server only use the least 128bit as the AES key.
            # we mask the least 128bit here.
            aes_key = utils.bit_mask(128) & (k_b << b)
            aes = AES.new(aes_key.to_bytes(16, 'big'))

            # send a dummy WUP request to obtain the server's attitude
            # towards the current hacked aes key.
            wups = WUP("I want to hack your aes key", self.mac, self.imei)
            encrypted_wups = [aes.encrypt(wup) for wup in wups]

            req = [(victim_id, C_b, wup) for wup in encrypted_wups]

            # update the hacked aes key according to server's respondence.
            k_b = (1-server.process_request(req)) << (127-b) | k_b

        # use the hacked AES key to encrypt another plain text
        victim_aes = k_b
        print("hacked aes key: {}".format(victim_aes))

        aes = AES.new(victim_aes.to_bytes(16, 'big'))

        wups = WUP("I hacked your aes key successfully", self.mac, self.imei)
        encrypted_wups = [aes.encrypt(wup) for wup in wups]

        req = [(victim_id, C, wup) for wup in encrypted_wups]
        assert server.process_request(req) == True, "hack failed"

        # further decrypt the victim request
        victim_text = ""
        for _, _, req in request:
            dt = aes.decrypt(req)
            text, checksum = dt[:-64], dt[-64:]

            content, mac, imei = text.decode('utf-8').split('\t')
            victim_text += content.strip()
        print("Victim WUP with plain text: {}".format(victim_text))

        return victim_aes


def test_hack(encode_method):
    user1 = Client(rsa_encode_method = encode_method)
    req1 = user1.send_request("wei cheng yong xiao is a good man.")

    server = Server()
    server.register(user1)

    attacker = Attacker()
    attacker.hack(user1.rsa.public_key, req1, server)


import os, random, utils

from rsa import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from typing import Dict, List, Tuple

def WUP(content: str, mac: str, imei: str) -> List[bytes]:
    """
    The format of the WUP request
    | content - 1024 bytes | mac - 7 bytes | imei - 7 bytes | SHA - 64 bytes |

    If the content is longer than 1024 bytes, we truncate it to pieces.
    """
    ret = []
    for i in range(0, len(content), 1024):
        sub_content = content[i: min(len(content), i + 1024)]
        if len(sub_content) < 1024:
            sub_content += " " * (1024 - len(sub_content))
        text = "\t".join([sub_content, mac, imei]).encode('utf-8')

        sha = SHA256.new()
        sha.update(text)
        checksum = sha.hexdigest().encode('utf-8')
        ret.append(text + checksum)
    return ret


class Client(object):
    def __init__(self, rsa_encode_method: str = "oaep"):
        self.id = random.randint(0, 1 << 64)
        self.rsa = RSA(encode_method = rsa_encode_method)    # RSA key pair of this user
        self.rsa.generate_key_pairs()

        # some sensitive private message
        self.mac = str(random.randint(1000000, 9999999))   # MAC address of user
        self.imei = str(random.randint(1000000, 9999999))  # IMEI series

    def send_request(self, content) -> List[Tuple]:
        """
        return a made up WUP request
        """
        
        # generate a 128-bit AES session key
        aes_key = random.getrandbits(128)
        aes = AES.new(aes_key.to_bytes(16, 'big'))

        # encrypt this session key using a 1024-bit RSA public key
        encrypted_aes_key = self.rsa.encrypt(aes_key)

        # use the AES session key to ecrypt the WUP request
        wups = WUP(content, self.mac, self.imei)
        encrypted_wups = [aes.encrypt(wup) for wup in wups]

        # send the RSA-encrypted AES session key and the 
        # encrypted WUP request to the server.
        return [(self.id, encrypted_aes_key, wup) for wup in encrypted_wups]

class Server(object):
    def __init__(self):
        # store the clients' RSA keys.
        self.client2rsa: Dict[int, RSA] = {}

    def register(self, client: Client) -> None:
        self.client2rsa[client.id] = client.rsa

    def process_request(self, request: List[Tuple]) -> bool:
        """
        process a WUP request sended by the user. 
        return True if it is a valid WUP request and False otherwise.

        Args:
        ----
            request: a listi of WUP request
        """
        request_user_id, encrypted_aes_key, _ = request[0]

        # decrypt the RSA-encrypted AES key it received from the client
        if request_user_id not in self.client2rsa.keys():
            print("The user of this request is not registered !")
            return False
        aes_key = self.client2rsa[request_user_id].decrypt(encrypted_aes_key, "int")
        aes_key = aes_key & utils.bit_mask(128)
        aes = AES.new(aes_key.to_bytes(16, 'big'))

        # decrypt the WUP request using the AES session key
        plain_text = ""
        for _, _, req in request:
            dt = aes.decrypt(req)
            text, checksum = dt[:-64], dt[-64:]

            sha = SHA256.new()
            sha.update(text)
            if checksum != sha.hexdigest().encode('utf-8'):
                # print(checksum)
                # print(sha.hexdigest().encode('utf-8'))
                print("Invalid WUP request. checksum not equal")
                return False

            content, mac, imei = text.decode('utf-8').split('\t')
            plain_text += content.strip()
        print("Valid WUP with plain text: {}".format(plain_text))
        return True


def test_communicate():
    user1 = Client()
    user2 = Client("naive")
    user3 = Client()
    server = Server()
    server.register(user1)
    server.register(user2)

    # user1 -> server
    req1 = user1.send_request("hello world")

    # user2 -> server
    req2 = user2.send_request("wei cheng yong xiao is a good man.")

    # user3 -> server
    req3 = user3.send_request("unregistered request")

    # server -> user3
    print(server.process_request(req3))

    # server -> user2
    print(server.process_request(req2))

    # server -> user1
    print(server.process_request(req1))


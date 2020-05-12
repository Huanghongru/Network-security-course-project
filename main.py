from rsa import test_rsa, test_oaep_encode_and_decode
from client_server import test_communicate
from attacker import test_hack

def main():
    test_rsa("naive")
    test_rsa("oaep")
    # test_oaep_encode_and_decode()
    # test_communicate()
    # test_hack()

if __name__ == "__main__":
    main()

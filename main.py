from rsa import test_rsa, test_oaep_encode_and_decode
from client_server import test_communicate
from attacker import test_hack

def main():
    print("="*20, "Test for Part 1", "="*20)
    test_rsa("naive")

    print("="*20, "Test for Part 2", "="*20)
    test_communicate()
    test_hack()

    print("="*20, "Test for Part 3", "="*20)
    test_rsa("oaep")
    test_oaep_encode_and_decode()

if __name__ == "__main__":
    main()

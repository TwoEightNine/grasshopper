import cipher
import os
import binascii

BLOCK_SIZE = cipher.BLOCK_SIZE

S_BOX_VALUES = {
    'in': [
        "ffeeddccbbaa99881122334455667700",
        "b66cd8887d38e8d77765aeea0c9a7efc",
        "559d8dd7bd06cbfe7e7b262523280d39",
        "0c3322fed531e4630d80ef5c5a81c50b"
    ],
    'out': [
        "b66cd8887d38e8d77765aeea0c9a7efc",
        "559d8dd7bd06cbfe7e7b262523280d39",
        "0c3322fed531e4630d80ef5c5a81c50b",
        "23ae65633f842d29c5df529c13f5acda"
    ]
}

R_TRANS_VALUES = {
    'in': [
        "00000000000000000000000000000100",
        "94000000000000000000000000000001",
        "a5940000000000000000000000000000",
        "64a59400000000000000000000000000"
    ],
    'out': [
        "94000000000000000000000000000001",
        "a5940000000000000000000000000000",
        "64a59400000000000000000000000000",
        "0d64a594000000000000000000000000"
    ]
}

L_TRANS_VALUES = {
    'in': [
        "64a59400000000000000000000000000",
        "d456584dd0e3e84cc3166e4b7fa2890d",
        "79d26221b87b584cd42fbc4ffea5de9a",
        "0e93691a0cfc60408b7b68f66b513c13"
    ],
    'out': [
        "d456584dd0e3e84cc3166e4b7fa2890d",
        "79d26221b87b584cd42fbc4ffea5de9a",
        "0e93691a0cfc60408b7b68f66b513c13",
        "e6a8094fee0aa204fd97bcb0b44b8580"
    ]
}

ENCRYPTION_VALUES = {
    'in': [
        "1122334455667700ffeeddccbbaa9988"
    ],
    'out': [
        "7f679d90bebc24305a468d42b9d4edcd"
    ]
}

MASTER_KEY = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"

ROUND_KEYS = [
    "8899aabbccddeeff0011223344556677",
    "fedcba98765432100123456789abcdef",
    "db31485315694343228d6aef8cc78c44",
    "3d4553d8e9cfec6815ebadc40a9ffd04",
    "57646468c44a5e28d3e59246f429f1ac",
    "bd079435165c6432b532e82834da581b",
    "51e640757e8745de705727265a0098b1",
    "5a7925017b9fdd3ed72a91a22286f984",
    "bb44e25378c73123a5f32f73cdb6e517",
    "72e9dd7416bcf45b755dbaa88e4a4043"
]


def test_random(func, func_inv, name, count=1000):
    for i in range(count):
        block = os.urandom(BLOCK_SIZE)
        assert block == func_inv(func(block)), name + " caused error with " + str(block)
    print(name + " passed with random!")


def test_values(func, inputs, outputs, name):
    for i in range(len(inputs)):
        given_input = binascii.unhexlify(inputs[i])
        expected_output = binascii.unhexlify(outputs[i])
        actual_output = func(given_input)
        assert expected_output == actual_output, \
            name + " caused error on test pair " + str(i) + " and gave " + str(actual_output)
    print(name + " passed with given test values!")


def test_round_keys():
    master_key = binascii.unhexlify(MASTER_KEY)
    round_keys = cipher.get_round_keys(master_key)
    expected_keys = [binascii.unhexlify(i) for i in ROUND_KEYS]
    assert round_keys == expected_keys, \
        "Round keys generator caused error: gave " + str(round_keys)
    print("Round keys generator passed!")


if __name__ == "__main__":
    # testing straight and invert functions on random blocks
    test_random(cipher.s_box, cipher.s_box_inv, "S-box")
    test_random(cipher.r_trans, cipher.r_trans_inv, "R-transition")
    test_random(cipher.l_trans, cipher.l_trans_inv, "L-transition")

    # testing functions on given values (from official paper)
    test_values(cipher.s_box, S_BOX_VALUES['in'], S_BOX_VALUES['out'], "S-box")
    test_values(cipher.r_trans, R_TRANS_VALUES['in'], R_TRANS_VALUES['out'], "R-transition")
    test_values(cipher.l_trans, L_TRANS_VALUES['in'], L_TRANS_VALUES['out'], "L-transition")

    # testing generator of round keys (from official paper)
    test_round_keys()

    # testing encryption and decryption (from official paper)
    key = binascii.unhexlify(MASTER_KEY)
    test_values(lambda block: cipher.encrypt_block(block, key), ENCRYPTION_VALUES['in'], ENCRYPTION_VALUES['out'], "Encryption")
    test_values(lambda block: cipher.decrypt_block(block, key), ENCRYPTION_VALUES['out'], ENCRYPTION_VALUES['in'], "Decryption")

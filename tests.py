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


if __name__ == "__main__":
    # testing straight and invert functions on random blocks
    test_random(cipher.s_box, cipher.s_box_inv, "S-box")
    test_random(cipher.r_trans, cipher.r_trans_inv, "R-transition")
    test_random(cipher.l_trans, cipher.l_trans_inv, "L-transition")

    # testing functions on given values (from official paper)
    test_values(cipher.s_box, S_BOX_VALUES['in'], S_BOX_VALUES['out'], "S-box")
    test_values(cipher.r_trans, R_TRANS_VALUES['in'], R_TRANS_VALUES['out'], "R-transition")
    test_values(cipher.l_trans, L_TRANS_VALUES['in'], L_TRANS_VALUES['out'], "L-transition")

import copy

DEBUG = True
f = open("debug.txt", "w")

enc_1, dec_9, enc_9, dec_1 = None, None, None, None


############################################################################
########################### HELPER FUNCTIONS ###############################
############################################################################
def debug(paramName, paramValue):
    if DEBUG:
        f.write(f"{paramName}: {paramValue}\n")


def hex_xor(a: str, b: str) -> str:
    """XOR two hexadecimal characters.

    Args:
        a (hex)
        b (hex)

    Returns:
        hexadecimal character
    """
    # Convert hexadecimal characters to integers
    a_int, b_int = int(a, 16), int(b, 16)

    # Perform XOR operation
    result_int = a_int ^ b_int

    # Convert result back to hexadecimal string
    result_hex = hex(result_int)[2:].zfill(2)
    return result_hex


def char_to_hex(ch: str):
    hex_val = hex(ord(ch))[2:]
    return hex_val


def print_all_words(key_schedule):
    if DEBUG:
        for i in range(0, 44):
            to_debug = f"Word {i}: "
            for j in range(4):
                to_debug += f"{key_schedule[i * 4 + j]} "
            f.write(to_debug + "\n")


def column_major_to_1d(matrix):
    return [matrix[row][col] for col in range(4) for row in range(4)]


def hex_to_chr(hex_val):
    decimal_val = int(hex_val, 16)
    ascii_char = chr(decimal_val)
    return ascii_char


############################################################################
############################## CONSTANTS ###################################
############################################################################

# fmt: off
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
INV_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
# fmt: on


############################################################################
############################# AES CLASS ####################################
############################################################################
class AES:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long")
        self.key = key

    def encrypt(self, plaintext: str) -> list[str]:
        global enc_1, enc_9
        # Pad with spaces to make it a multiple of 16 bytes
        if len(plaintext) % 16 != 0:
            plaintext = plaintext + " " * (16 - len(plaintext) % 16)

        self.plain_state = self.convertToMatrix(plaintext)
        debug("Initial plain_state", self.plain_state)

        self.key_matrix = self.convertToHexList(self.key)
        self.key_schedule = self.key_expansion(self.key_matrix)

        print_all_words(self.key_schedule)

        # Add the first round key to the state before starting the rounds.
        self.add_round_key(0)
        debug("state after 0", self.plain_state)

        # Out of 10 rounds, first 9 are indetical
        for i in range(1, 10):
            self.sub_bytes_plain_state()
            self.shift_rows()
            self.mix_column_using_precomputed_values()
            self.add_round_key(i)
            if i == 1:
                # print("enc_1", self.plain_state)
                enc_1 = copy.deepcopy(self.plain_state)
            debug(f"state after {i}", self.plain_state)

        enc_9 = copy.deepcopy(self.plain_state)
        # print("enc_9", self.plain_state)

        # The MixColumns function is not present in the last round.
        self.sub_bytes_plain_state()
        self.shift_rows()
        self.add_round_key(10)
        debug("state after 10", self.plain_state)

        return self.plain_state

    ############################################################################
    ########################### UTIL FUNCTIONS #################################
    ############################################################################
    def convertToMatrix(self, text: str):
        matrix = [[0x00 for i in range(4)] for j in range(4)]
        for i, char in enumerate(text):
            matrix[i % 4][i // 4] = char_to_hex(char)
        return matrix

    def convertToHexList(self, text: str):
        return [char_to_hex(char) for char in text]

    def key_expansion(self, key):
        """Expands the 16-byte key into the 176-byte key schedule for AES-128."""
        # Convert the key from a 4x4 column major matrix of hex values to a list of bytes

        # The first 16 bytes of the key schedule are the key itself
        key_schedule = key[:]

        # The next 160 bytes are filled with 10 rounds of 16 bytes each
        for i in range(1, 11):
            # The first 4 bytes of the round key are the last 4 bytes of the previous round key
            # rotated left by one byte and then substituted with the S-box.
            # The last 12 bytes of the round key are the previous 12 bytes XORed with the first 12 bytes
            # of the previous round key.
            round_constant = RCON[i - 1]
            new_bytes = []
            for j in range(4):
                if j == 0:
                    # Rotate left the last 4 bytes of the previous round key
                    rotated_bytes = key_schedule[-4:]
                    rotated_bytes = self.rotate_left_by(rotated_bytes, 1)

                    # Substitute the bytes with the S-box
                    substituted_bytes = self.sub_bytes(rotated_bytes)

                    # XOR the first byte with the round constant
                    substituted_bytes[0] = hex(
                        round_constant ^ int(substituted_bytes[0], 16)
                    )[2:].zfill(2)

                    # XOR with W(i-3)
                    Wn_3 = key_schedule[-16:-12]
                    for i in range(4):
                        substituted_bytes[i] = hex(
                            int(substituted_bytes[i], 16) ^ int(Wn_3[i], 16)
                        )[2:].zfill(2)

                    new_bytes.extend(substituted_bytes)

                else:
                    # XOR the corresponding bytes of the previous round key and the new bytes
                    start, end = -16 + j * 4, -12 + j * 4
                    if end != 0:
                        old_bytes = key_schedule[start:end]
                    else:
                        old_bytes = key_schedule[start:]

                    new_bytes.extend(
                        [hex_xor(a, b) for a, b in zip(old_bytes, new_bytes[-4:])]
                    )

            key_schedule += new_bytes
        return key_schedule

    def rotate_left_by(self, arr, offset):
        """Rotates the arr of 4 bytes to the left by <offset> bytes"""
        return arr[offset:] + arr[:offset]

    def sub_bytes(self, arr):
        """Substitutes each byte in the state with the corresponding byte in the S-box. Outpu as bytearray"""
        return [hex(S_BOX[int(b, 16)])[2:].zfill(2) for b in arr]

    def sub_bytes_plain_state(self):
        """Substitutes each byte in the state with the corresponding byte in the S-box. Output as bytearray"""
        for i in range(4):
            self.plain_state[i] = self.sub_bytes(self.plain_state[i])

    def shift_rows(self):
        """Shifts the rows in the state to the left."""
        self.plain_state[1] = self.rotate_left_by(self.plain_state[1], 1)
        self.plain_state[2] = self.rotate_left_by(self.plain_state[2], 2)
        self.plain_state[3] = self.rotate_left_by(self.plain_state[3], 3)

    def add_round_key(self, round):
        """Adds the round key to the state. plain_state is 4x4 hex"""
        start, end = round * 16, (round + 1) * 16
        round_key = self.key_schedule[start:end]
        debug(f"Round Key {round}", round_key)
        for i in range(4):
            for j in range(4):
                self.plain_state[i][j] = hex_xor(
                    self.plain_state[i][j], round_key[i + 4 * j]
                )

    def mix_column_using_precomputed_values(self):
        """Using precomputed values to mix the columns of the state."""
        MIX_COLUMNS_MATRIX = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02],
        ]
        result = [[0 for i in range(4)] for j in range(4)]

        # iterating by row of A
        for i in range(4):
            # iterating by col of B
            for j in range(4):
                sum = 0
                # iterating by row of b
                for k in range(4):
                    mult = self.GF_mult(
                        int(MIX_COLUMNS_MATRIX[i][k]), int(self.plain_state[k][j], 16)
                    )
                    # In GF(2^8), addition is the same as XOR
                    sum ^= mult
                result[i][j] = hex(sum % 256)[2:].zfill(2)
        self.plain_state = result

    def GF_mult(self, a, b):
        p = 0
        for i in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B
            b >>= 1
        return p

    def decrypt(self, ciphertext):
        """Decrypts the ciphertext with the key"""
        global dec_1, dec_9
        self.plain_state = ciphertext
        debug("state after 10", self.plain_state)

        self.add_round_key(10)

        debug("state after 9", self.plain_state)

        for i in range(9, 0, -1):
            self.inv_shift_rows()
            self.inv_sub_bytes()
            if i == 9:
                dec_1 = copy.deepcopy(self.plain_state)
            elif i == 1:
                dec_9 = copy.deepcopy(self.plain_state)

            self.add_round_key(i)
            self.inv_mix_columns_with_precom()
            debug(f"state after {i-1}:", self.plain_state)

        self.inv_shift_rows()
        self.inv_sub_bytes()
        self.add_round_key(0)
        debug("Intial Plain State", self.plain_state)

        return self.plain_state

    def inv_shift_rows(self):
        """Shifts the rows in the state to the right."""
        self.plain_state[1] = self.rotate_left_by(self.plain_state[1], -1)
        self.plain_state[2] = self.rotate_left_by(self.plain_state[2], -2)
        self.plain_state[3] = self.rotate_left_by(self.plain_state[3], -3)

    def inv_sub_bytes(self):
        """Substitutes the bytes in the state with the inverse S-box."""
        for i in range(4):
            for j in range(4):
                self.plain_state[i][j] = hex(
                    INV_S_BOX[int(self.plain_state[i][j], 16)]
                )[2:].zfill(2)

    def inv_mix_columns_with_precom(self):
        INV_MIX_COLUMNS_MATRIX = [
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E],
        ]
        result = [[0 for i in range(4)] for j in range(4)]

        # iterating by row of A
        for i in range(4):
            # iterating by col of B
            for j in range(4):
                sum = 0
                # iterating by row of b
                for k in range(4):
                    mult = self.GF_mult(
                        int(INV_MIX_COLUMNS_MATRIX[i][k]),
                        int(self.plain_state[k][j], 16),
                    )
                    # In GF(2^8), addition is the same as XOR
                    sum ^= mult
                result[i][j] = hex(sum % 256)[2:].zfill(2)
        self.plain_state = result


class plaintext_key_pair:
    def __init__(self, plaintext, key):
        self.plaintext = plaintext
        self.key = key


if __name__ == "__main__":
    # [Plaintext, Key]
    plaintext_key_pairs = [
        plaintext_key_pair("Two One Nine Two", "Thats my Kung Fu"),
        plaintext_key_pair("Need Padding", "aBcDeFgHiJkLmNoP"),
        plaintext_key_pair("aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa"),
    ]

    for i, pair in enumerate(plaintext_key_pairs):
        print(f"---------- Test Case {i} ----------")
        print("Plaintext: ", pair.plaintext)
        print("Key:", pair.key)
        aes = AES(pair.key)
        ciphertext = aes.encrypt(pair.plaintext)
        print("ciphertext:", column_major_to_1d(ciphertext))

        decrypted_plaintext = aes.decrypt(ciphertext)

        print("Decrypted plaintext:", end=" ")
        for i in column_major_to_1d(decrypted_plaintext):
            print(hex_to_chr(i), end="")
        print("\n")

        print("dec_1", dec_1)
        print("enc_9", enc_9)
        print(f"Is Dec_1 == Enc_9?  >>{enc_9 == dec_1}")
        print()
        print("dec_9", dec_9)
        print("enc_1", enc_1)
        print(f"Is Dec_9 == Enc_1?  >>{enc_1 == dec_9}")
        print("\n\n")
        # exit(0)
    f.close()

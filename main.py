import constants
import binascii

plaintext = "abcdabcdabcdabcd"  # 16 bytes, 128 bits
key = "abcdEFGHijklMNOP"  # 16 bytes, 128 bits
# key = "2b7e151628aed2a6abf7158809cf4f3c"
DEBUG = True


def debug(param, paramname):
    if DEBUG:
        print(paramname, ":", param)


def debugByteArray(byte_arr, arr_name):
    if DEBUG:
        print(arr_name, end=": ")
        for byte in byte_arr:
            print(chr(byte), end="")
        print()


class AES:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long")
        self.key = key

    # def convert_hex_or_str(self, text):
    #     "converts str to hex, or hex to str"
    #     if type(text) == str:
    #         return binascii.hexlify(text.encode())
    #     else:
    #         return binascii.unhexlify(text).decode()

    def convertToMatrix(self, text):
        """plaintext ascii string to 4x4 matrix column wise as byte. Padding with null bytes if needed"""
        matrix = [[b"\0" for i in range(4)] for j in range(4)]
        for i in range(min(16, len(text))):
            matrix[i % 4][i // 4] = text[i].encode("utf-8")
        return matrix

    def convertToByteArray(self, text):
        """converts ascii string to bytearray"""
        return bytearray(text, "utf-8")

    def key_expansion(self, key):
        """Expands the 16-byte key into the 176-byte key schedule for AES-128."""
        # The first 16 bytes of the key schedule are the key itself
        key_schedule = key[:]

        # The next 160 bytes are filled with 10 rounds of 16 bytes each
        for i in range(1, 11):
            # The first 4 bytes of the round key are the last 4 bytes of the previous round key
            # rotated left by one byte and then substituted with the S-box.
            x1 = self.rotate_left_by(key_schedule[-4:], 1)
            debugByteArray(x1, "x1")

            x2 = self.sub_bytes(x1)
            debug(x2, "x2")

            # without rcon
            # x3 = [x2[0] ^ key_schedule[-16], x2[1] ^ key_schedule[-15], x2[2] ^ key_schedule[-14], x2[3] ^ key_schedule[-13]]

            exit(0)

            # The last 12 bytes of the round key are the previous 12 bytes XORed with the first 12 bytes
            # of the previous round key.
            key_schedule += [
                key_schedule[-16] ^ key_schedule[-12],
                key_schedule[-15] ^ key_schedule[-11],
                key_schedule[-14] ^ key_schedule[-10],
                key_schedule[-13] ^ key_schedule[-9],
                key_schedule[-8] ^ key_schedule[-4],
                key_schedule[-7] ^ key_schedule[-3],
                key_schedule[-6] ^ key_schedule[-2],
                key_schedule[-5] ^ key_schedule[-1],
            ]

        return key_schedule

    def rotate_left_by(self, arr, offset):
        """Rotates the arr of 4 bytes to the left by <offset> bytes"""
        return arr[offset:] + arr[:offset]

    def sub_bytes(self, arr):
        """Substitutes each byte in the state with the corresponding byte in the S-box."""
        return [constants.S_BOX[b] for b in arr]

    def encrypt(self, plaintext):
        # if len(plaintext) != 16:
        #     raise ValueError("Plaintext must be 16 bytes long")

        self.plain_state = self.convertToMatrix(plaintext)
        debug(self.plain_state, "plain_state")

        self.key_byte_arr = self.convertToByteArray(self.key)
        debugByteArray(self.key_byte_arr, "key_byte_arr")

        self.key_schedule = self.key_expansion(self.key_byte_arr)

        # key_hex = self.convert_hex_or_str(self.key)
        # self.key_state = self.convertToMatrix(key_hex)

        exit(0)

        # Add the first round key to the state before starting the rounds.
        self.add_round_key(self.plain_state, self.key_state)

        # There are 10 rounds.
        # The first 9 rounds are identical.
        # These 9 rounds are executed in the loop below.
        for i in range(9):
            self.sub_bytes(self.plain_state)
            self.shift_rows(self.plain_state)
            self.mix_columns(self.plain_state)
            self.add_round_key(self.plain_state, self.key_state)

        # The last round is given below.
        # The MixColumns function is not here in the last round.
        self.sub_bytes(self.plain_state)
        self.shift_rows(self.plain_state)
        self.add_round_key(self.plain_state, self.key_state)

        return self.plain_state

    def add_round_key(self, state, key):
        """Adds the round key to the state."""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= key[i][j]

    def shift_rows(self, state):
        """Shifts the rows in the state to the left."""
        for i in range(4):
            state[i] = state[i].rotate_left(i)

    def mix_columns(self, state):
        """Mixes the columns of the state."""
        for i in range(4):
            # The method below puts the product of {02} and the column in temp.
            t = self.xtime(state[i][0])
            # Then it is XORed with the column with an offset of 1.
            # This is all done modulo {1b}.
            state[i][0] ^= t ^ self.xtime(state[i][1]) ^ state[i][1]
            state[i][1] ^= t ^ self.xtime(state[i][2]) ^ state[i][2]
            state[i][2] ^= t ^ self.xtime(state[i][3]) ^ state[i][3]
            state[i][3] ^= t ^ self.xtime(state[i][0]) ^ state[i][0]

    def xtime(self, byte):
        """Multiplies {02} with the byte modulo {1b}."""
        return ((byte << 1) ^ 0x1B) if (byte & 0x80) else (byte << 1)


if __name__ == "__main__":
    aes = AES(key)
    ciphertext = aes.encrypt(plaintext)
    print(ciphertext)

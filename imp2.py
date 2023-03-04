import constants


def key_expansion(key):
    # Rcon values for key schedule
    rcon = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

    # SubWord function
    def sub_word(word):
        return (
            constants.S_BOX[word >> 24] << 24
            | constants.S_BOX[(word >> 16) & 0xFF] << 16
            | constants.S_BOX[(word >> 8) & 0xFF] << 8
            | constants.S_BOX[word & 0xFF]
        )

    # RotWord function
    def rot_word(word):
        return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

    # Initialize key schedule with original key
    key_schedule = [0] * 44
    for i in range(4):
        key_schedule[i] = (key >> (24 - i * 8)) & 0xFF

    # Generate remaining key schedule values
    for i in range(4, 44):
        temp = key_schedule[i - 1]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp)) ^ rcon[i // 4 - 1]
        key_schedule[i] = key_schedule[i - 4] ^ temp

    return key_schedule


# Add round key
def add_round_key(state, key_schedule, round_num):
    key_start = round_num * 16
    key = key_schedule[key_start : key_start + 16]

    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i * 4 + j]


# SubBytes
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = constants.S_BOX[state[i][j]]


# ShiftRows
def shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]


# MixColumns
def mix_columns(state):
    def mix_column(col):
        tmp = col[0] ^ col[1] ^ col[2] ^ col[3]
        t = col[0] ^ col[1]
        t = xtime(t)
        state[0] = col[0] ^ t ^ tmp
        t = col[1] ^ col[2]
        t = xtime(t)
        state[1] = col[1] ^ t ^ tmp
        t = col[2] ^ col[3]
        t = xtime(t)
        state[2] = col[2] ^ t ^ tmp
        t = col[3] ^ col[0]
        t = xtime(t)
        state[3] = col[3] ^ t ^ tmp

    for i in range(4):
        col = [state[j][i] for j in range(4)]
        mix_column(col)
        for j in range(4):
            state[j][i] = col[j]


def encrypt_AES_128(plaintext, key):
    # Key schedule
    key_words = [key[i : i + 4] for i in range(0, len(key), 4)]
    key_schedule = key_expansion(key_words)

    # Padding the plaintext if necessary
    if len(plaintext) % 16 != 0:
        plaintext += b"\x00" * (16 - len(plaintext) % 16)

    # Breaking the plaintext into 16-byte blocks and encrypting each one
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        state = [[plaintext[j + i] for j in range(4)] for i in range(0, 16, 4)]

        # Initial round
        state = add_round_key(state, key_schedule[:4])

        # Main rounds
        for j in range(4, 4 * 10, 4):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, key_schedule[j : j + 4])

        # Final round
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, key_schedule[40:])

        # Converting the state matrix to a byte string and appending it to the ciphertext
        ciphertext += bytes([state[j][i] for i in range(4) for j in range(4)])

    return ciphertext

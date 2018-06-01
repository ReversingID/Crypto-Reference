# Hash function by Arash Partow
# Archive of Reversing.ID
# Non-Cryptographic Hash

def APHash(key):
    state = 0xAAAAAAAA

    for i in range(len(key)):
        if ((i & 1) == 0):
            state ^= ((state <<  7) ^ ord(key[i]) * (state >> 3))
        else:
            state ^= (~((state << 11) + ord(key[i]) ^ (state >> 5)))
    return state
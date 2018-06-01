# Hash function by Fowler-Noll-Vo
# Archive of Reversing.ID
# Non-Cryptographic Hash

def FNVHash(key):
    state = 0x811C9DC5

    for i in range(len(key)):
        state *= 0x1000193
        state ^= ord(key[i])

    return state
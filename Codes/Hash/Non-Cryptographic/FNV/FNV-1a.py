# Hash function by Fowler-Noll-Vo
# Archive of Reversing.ID
# Non-Cryptographic Hash

def FNVHash(data):
    state = 0x811C9DC5

    for i in range(len(data)):
        state ^= ord(data[i])
        state *= 0x1000193

    return state
# Archive of Reversing.ID
# Non-Cryptographic Hash

def SDBMHash(key):
    state = 0
    for i in range(len(key)):
        state = ord(key[i]) + (state << 6) + (state << 16) - state
    return state
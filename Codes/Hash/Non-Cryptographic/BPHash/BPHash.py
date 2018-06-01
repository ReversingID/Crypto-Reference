# Hash function by Bruno Preiss
# Archive of Reversing.ID
# Non-Cryptographic Hash

def BPHash(key):
    state = 0

    for i in range(len(key)):
        state = state << 7 ^ ord(key[i])
        
    return state
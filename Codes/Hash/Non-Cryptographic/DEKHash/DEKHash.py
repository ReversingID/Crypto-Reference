# Hash function by Donald E. Knuth
# Archive of Reversing.ID
# Non-Cryptographic Hash

def DEKHash(key):
    state = len(key)

    for i in range(len(key)):
        state = ((state << 5) ^ (state >> 27)) ^ ord(key[i])
        
    return state
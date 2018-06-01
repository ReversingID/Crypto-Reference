# Hash function by Daniel J. Bernstein
# Archive of Reversing.ID
# Non-Cryptographic Hash

def DJBHash(key):
    state = 5381

    for i in range(len(key)):
        state = ((state << 5) + state) + ord(key[i])
        
    return state
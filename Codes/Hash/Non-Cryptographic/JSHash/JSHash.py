# Hash function by Justin Sobel
# Archive of Reversing.ID
# Non-Cryptographic Hash
    
def JSHash(key):
    state = 1315423911

    for i in range(len(key)):
        state ^= ((state << 5) + ord(key[i]) + (state >> 2))
        
    return state
# Hash function by Brian Kernighan & Dennis Ritchie
# Archive of Reversing.ID
# Non-Cryptographic Hash

def BKDRHash(key):
    seed = 131 # 31 131 1313 13131 131313 etc..
    state = 0

    for i in range(len(key)):
        state = (state * seed) + ord(key[i])
        
    return state
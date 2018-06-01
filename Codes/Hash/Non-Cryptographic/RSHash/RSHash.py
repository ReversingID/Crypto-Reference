# Hash function by Robert Sedgwicks
# Archive of Reversing.ID
# Non-Cryptographic Hash

def RSHash(key):
    a     = 378551
    b     =  63689
    state =      0

    for i in range(len(key)):
        state = state * a + ord(key[i])
        a = a * b
    
    return state
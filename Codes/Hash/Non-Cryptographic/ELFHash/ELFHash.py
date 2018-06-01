# Modifikasi PJWHash untuk sistem UNIX.
# Archive of Reversing.ID
# Non-Cryptographic Hash

def ELFHash(key):
    state = 0
    test  = 0

    for i in range(len(key)):
        state = (state << 4) + ord(key[i])
        
        test = state & 0xF0000000
        if test != 0:
            state ^= (test >> 24)
        
        state &= ~test
    
    return state
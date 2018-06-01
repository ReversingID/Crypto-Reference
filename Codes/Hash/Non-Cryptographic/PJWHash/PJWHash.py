# Hash function by Peter J. Weinberger
# Archive of Reversing.ID
# Non-Cryptographic Hash

def PJWHash(key):
    BitsInUnsignedInt = 4 * 8
    ThreeQuarters     = long((BitsInUnsignedInt  * 3) / 4)
    OneEighth         = long(BitsInUnsignedInt / 8)
    HighBits          = (0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth)
    state             = 0
    test              = 0

    for i in range(len(key)):
        state = (state << OneEighth) + ord(key[i])
        
        test = state & HighBits
        if test != 0:
            state = (( state ^ (test >> ThreeQuarters)) & (~HighBits))
        
    return (state & 0x7FFFFFFF)
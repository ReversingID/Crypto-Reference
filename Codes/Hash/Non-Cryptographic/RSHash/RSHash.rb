# Hash function by Robert Sedgwicks
# Archive of Reversing.ID
# Non-Cryptographic Hash

def rshash( key, len=key.length )
    a     = 63689
    b     = 378551
    state = 0

    len.times{ |i|
        state = state * a + key[i]
        a *= b
    }
    return state
end
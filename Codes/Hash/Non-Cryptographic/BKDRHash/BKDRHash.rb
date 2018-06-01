# Hash function by Brian Kernighan & Dennis Ritchie
# Archive of Reversing.ID
# Non-Cryptographic Hash

def bkdrhash( key, len=key.length )
    seed  = 131    # 31 131 1313 13131 131313 etc..
    state = 0

    len.times{ |i|
        state = ( state * seed ) + key[i]
    }
    return state
end
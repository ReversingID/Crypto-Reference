# Hash function by Donald E. Knuth
# Archive of Reversing.ID
# Non-Cryptographic Hash

def dekhash( key, len=key.length )
    state = len
    
    len.times{ |i|
        state = ((state << 5) ^ (state >> 27)) ^ key[i]
    }
    return state
end
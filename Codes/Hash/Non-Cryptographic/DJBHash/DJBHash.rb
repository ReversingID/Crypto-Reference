# Hash function by Daniel J. Bernstein
# Archive of Reversing.ID
# Non-Cryptographic Hash

def djbhash( key, len=key.length )
    state = 5381
    
    len.times{ |i|
        state = ((state << 5) + state) + key[i]
    }
    return state
end
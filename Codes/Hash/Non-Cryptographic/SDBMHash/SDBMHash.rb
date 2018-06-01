# Archive of Reversing.ID
# Non-Cryptographic Hash

def sdbmhash( key, len=key.length )
    state = 0
    
    len.times{ |i|
        state = key[i] + ( state << 6 ) + ( state << 16 ) - state
    }
    return state
end
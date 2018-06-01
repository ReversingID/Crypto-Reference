# Hash function by Bruno Preiss
# Archive of Reversing.ID
# Non-Cryptographic Hash

def bphash( key, len=key.length )
    state = 0
    
    len.times{ |i|
        state = state << 7 ^ key[i]
    }
    return state
end

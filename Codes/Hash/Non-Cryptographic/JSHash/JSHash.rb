# Hash function by Justin Sobel
# Archive of Reversing.ID
# Non-Cryptographic Hash
    
def jshash( key, len=key.length )
    state = 1315423911
    len.times{ |i|
        state ^= ( ( state << 5 ) + key[i] + ( state >> 2 ) )
    }
    return state
end
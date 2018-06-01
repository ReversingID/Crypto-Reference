# Hash function by Arash Partow
# Archive of Reversing.ID
# Non-Cryptographic Hash

def aphash( key, len=key.length )
    state = 0xAAAAAAAA
    len.times{ |i|
        if (i & 1) == 0
            state ^= (state << 7) ^ key[i] * (state >> 3)
        else
            state ^= ~( (state << 11) + key[i] ^ (state >> 5) )
        end
    }
    return state
end
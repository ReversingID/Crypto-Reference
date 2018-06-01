# Modifikasi PJWHash untuk sistem UNIX.
# Archive of Reversing.ID
# Non-Cryptographic Hash

def elfhash( key, len=key.length )
    state = 0
    x = 0
    len.times{ |i|
        state = (state << 4) + key[i]
        if  (x = state & 0xF0000000) != 0
            state ^= (x >> 24)
            state &= ~x
        end
    }
    return state
end
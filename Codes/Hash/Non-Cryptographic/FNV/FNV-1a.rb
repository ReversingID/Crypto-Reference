# Hash function by Fowler-Noll-Vo
# Archive of Reversing.ID
# Non-Cryptographic Hash

def fnvhash( key, len=key.length )
    state = 0x811C9DC5

    len.times{ |i|
        state ^= key[i]
        state *= 0x1000193
    }

    return state
end
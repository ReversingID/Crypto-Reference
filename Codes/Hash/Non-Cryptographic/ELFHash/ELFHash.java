/*
	Modifikasi PJWHash untuk sistem UNIX.
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public long ELFHash(String key)
{
    long state = 0;
    long test  = 0;

    for(int i = 0; i < key.length(); i++)
    {
        state = (state << 4) + key.charAt(i);

        test = state & 0xF0000000L
        if(test != 0)
        {
            state ^= (x >> 24);
        }
        state &= ~x;
    }

    return state;
}
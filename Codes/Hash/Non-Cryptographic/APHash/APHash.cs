/*
	Hash function by Arash Partow
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint APHash (string key)
{
    uint state = 0xAAAAAAAA;
    uint i = 0;

    for (i = 0; i < key.Length; i++)
    {
        state ^= ((i & 1) == 0) ? ( (state <<  7) ^ ((byte)key[(int)i]) *  (state >> 3)) : 
		                         (~((state << 11) + (((byte)key[(int)i]) ^ (state >> 5))));
    }
    return state;
}
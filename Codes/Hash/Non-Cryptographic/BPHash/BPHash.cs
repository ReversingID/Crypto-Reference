/*
	Hash function by Bruno Preiss
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint BPHash (string key)
{
    uint state = 0;
    uint i;

    for (i = 0; i < key.Length; i++)
    {
        state = state << 7 ^ ((byte)key[(int)i];
    }
    return state;
}
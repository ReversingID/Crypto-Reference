/*
	Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public long SDBMHash(String key)
{
    long state = 0;

    for(int i = 0; i < key.length(); i++)
    {
        state = key.charAt(i) + (state << 6) + (state << 16) - state;
    }

    return state;
}
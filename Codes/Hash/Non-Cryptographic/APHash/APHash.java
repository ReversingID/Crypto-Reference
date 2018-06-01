/*
	Hash function by Arash Partow
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static long APHash (String key)
{
    long state = 0xAAAAAAAA;

    for (long i = 0; i < key.length(); i++)
    {
        if ((i & 1) == 0)
        {
            state ^=   ((state << 7) ^ key.charAt(i) *  (state >> 3));
        }
        else
        {
            state ^= (~((state << 11) + key.charAt(i) ^ (state >> 5)));
        }
    }
    return state;
}
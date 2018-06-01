/*
	Hash function by Donald E. Knuth
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static long DEKHash(String key)
{
    long state = key.length();

    for(int i = 0; i < key.length(); i++)
    {
        state = ((state << 5) ^ (state >> 27)) ^ key.charAt(i);
    }

    return state;
}
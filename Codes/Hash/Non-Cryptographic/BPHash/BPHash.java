/*
	Hash function by Bruno Preiss
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static long BPHash(String key)
{
    long state = 0;

    for(int i = 0; i < key.length(); i++)
    {
        state = state << 7 ^ key.charAt(i);
    }

    return state;
}
/*
	Hash function by Brian Kernighan & Dennis Ritchie
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public long BKDRHash(String key)
{
    long seed = 131;    // 31 131 1313 13131 131313 etc..
    long state = 0;

    for(int i = 0; i < key.length(); i++)
    {
        state = (state * seed) + key.charAt(i);
    }

    return state;
}
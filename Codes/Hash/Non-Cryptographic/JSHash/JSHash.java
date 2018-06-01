/*
	Hash function by Justin Sobel
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public long JSHash(String key)
{
    long state = 1315423911;

    for(int i = 0; i < key.length(); i++)
    {
        state ^= ((state << 5) + key.charAt(i) + (state >> 2));
    }
    return state;
}
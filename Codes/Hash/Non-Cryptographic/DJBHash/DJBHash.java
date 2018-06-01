/*
	Hash function by Daniel J. Bernstein
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public long DJBHash(String key)
{
    long state = 5381;

    for(int i = 0; i < key.length(); i++)
    {
        state = ((state << 5) + state) + key.charAt(i);
    }

    return state;
}
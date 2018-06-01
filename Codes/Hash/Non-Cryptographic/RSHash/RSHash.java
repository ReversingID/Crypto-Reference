/*
	Hash function by Robert Sedgwicks in C book.
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static long RSHash(String key)
{
    int b     = 378551;
    int a     = 63689;
    long state = 0;

    for(int i = 0; i < key.length(); i++)
    {
        state = state * a + key.charAt(i);
        a    = a * b;
    }

    return state;
}
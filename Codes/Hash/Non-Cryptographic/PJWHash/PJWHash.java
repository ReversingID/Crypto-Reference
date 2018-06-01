/*
	Hash function by Peter J. Weinberger
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public long PJWHash(String key)
{
    long BitsInUnsignedInt = (long)(4 * 8);
    long ThreeQuarters     = (long)((BitsInUnsignedInt  * 3) / 4);
    long OneEighth         = (long)(BitsInUnsignedInt / 8);
    long HighBits          = (long)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
    long state             = 0;
    long test              = 0;

    for(int i = 0; i < key.length(); i++)
    {
        state = (state << OneEighth) + key.charAt(i);

        test = state & HighBits;
        if(test != 0)
        {
            state = (( state ^ (test >> ThreeQuarters)) & (~HighBits));
        }
    }

    return state;
}
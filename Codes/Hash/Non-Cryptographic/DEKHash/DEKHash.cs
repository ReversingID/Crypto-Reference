/*
	Hash function by Donald E. Knuth
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint DEKHash (string key)
{
    uint state = (uint)key.Length;
	uint i = 0;

	for (i = 0; i < key.Length; i++)
	{
		state = ((state << 5) ^ (state >> 27)) ^ ((byte)key[(int)i]);
	}
	
	return state;
}
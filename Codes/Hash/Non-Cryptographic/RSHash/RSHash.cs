/*
	Hash function by Robert Sedgwicks
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint RSHash (string key)
{
    uint b = 378551;
	uint a = 63689;
	uint state = 0;
	uint i = 0;

	for (i = 0; i < key.Length; i++)
	{
		state = state * a + ((byte)key[(int)i]);
		a *= b;
	}

	return state;
}
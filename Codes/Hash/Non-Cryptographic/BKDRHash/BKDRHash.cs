/*
	Hash function by Brian Kernighan & Dennis Ritchie
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint BKDRHash (string key)
{
    uint seed  = 131;
	uint state = 0;
	uint i = 0;

	for (i = 0; i < key.Length; i++)
	{
		state = (state * seed) + ((byte)key[(int)i]);
	}

	return state;
}
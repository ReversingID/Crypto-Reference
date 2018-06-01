/*
	Hash function by Justin Sobel
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint JSHash (string key)
{
    uint state = 1315423911;
	uint i = 0;

	for (i = 0; i < key.Length; i++)
	{
		state ^= ((state << 5) + ((byte)key[(int)i]) + (state >> 2));
	}

	return state;
}
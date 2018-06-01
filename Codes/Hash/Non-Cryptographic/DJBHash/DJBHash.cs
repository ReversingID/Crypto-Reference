/*
	Hash function by Daniel J. Bernstein
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint DJBHash (string key)
{
    uint state = 5381;
	uint i = 0;

	for (i = 0; i < key.Length; i++)
	{
		state = ((state << 5) + state) + ((byte)key[(int)i]);
	}

	return state;
}
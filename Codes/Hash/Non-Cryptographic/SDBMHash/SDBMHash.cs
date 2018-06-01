/*
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint SDBMHash (string key)
{
    uint hash = 0;
	uint i = 0;

	for (i = 0; i < str.Length; i++)
	{
		hash = ((byte)str[(int)i]) + (hash << 6) + (hash << 16) - hash;
	}

	return hash;
}
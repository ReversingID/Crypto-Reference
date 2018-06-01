/*
	Modifikasi PJWHash untuk sistem UNIX.
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint ELFHash (string key)
{
    uint state = 0;
	uint x = 0;
	uint i = 0;

	for (i = 0; i < key.Length; i++)
	{
		state = (state << 4) + ((byte)key[(int)i]);
		
		if ((x = state & 0xF0000000) != 0)
		{
			state ^= (x >> 24);
		}
		
		state &= ~x;
	}

	return state;
}
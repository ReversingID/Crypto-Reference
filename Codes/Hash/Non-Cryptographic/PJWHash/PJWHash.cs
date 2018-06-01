/*
	Hash function by Peter J. Weinberger
    Archive of Reversing.ID
    Non-Cryptographic Hash
*/

// Fungsi ini merupakan method dari sebuah class
public static uint PJWHash (string key)
{
    const uint BitsInUnsignedInt = (uint)(sizeof(uint) * 8);
	const uint ThreeQuarters = (uint)((BitsInUnsignedInt * 3) / 4);
	const uint OneEighth = (uint)(BitsInUnsignedInt / 8);
	const uint HighBits = (uint)(0xFFFFFFFF) << (int)(BitsInUnsignedInt - OneEighth);
	uint state = 0;
	uint test = 0;
	uint i = 0;

	for (i = 0; i < key.Length; i++)
	{
		state = (state << (int)OneEighth) + ((byte)key[(int)i]);

		if ((test = state & HighBits) != 0)
		{
			state = ((state ^ (test >> (int)ThreeQuarters)) & (~HighBits));
		}
	}

	return state;
}
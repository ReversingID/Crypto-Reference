'  Hash function by Peter J. Weinberger
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function PJWFHash (key As String) As UInteger
    Const BitsInUnsignedInt As UInteger = CUInt(4 * 8)
	Const ThreeQuarters As UInteger = CUInt((BitsInUnsignedInt * 3) / 4)
	Const OneEighth As UInteger = CUInt(BitsInUnsignedInt \ 8)
	Const HighBits As UInteger = CUInt(&HFFFFFFFFUI) << CInt(BitsInUnsignedInt - OneEighth)
	Dim state As UInteger = 0
	Dim test As UInteger = 0
	Dim i As UInteger = 0

	For i = 0 To key.Length - 1
		state = (state << CInt(OneEighth)) + CByte(AscW(key(CInt(i))))
		test = state And HighBits

		If test <> 0 Then
			state = ((state Xor (test >> CInt(ThreeQuarters))) And (Not HighBits))
		End If
	Next

	Return state
End Function
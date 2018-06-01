'  Hash function by Donald E. Knuth
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function DEKHash (key As String) As UInteger
    Dim state As UInteger = CUInt(key.Length)
	Dim i As UInteger = 0

	For i = 0 To key.Length - 1
		state = ((state << 5) Xor (state >> 27)) Xor CByte(AscW(key(CInt(i))))
	Next

	Return state
End Function
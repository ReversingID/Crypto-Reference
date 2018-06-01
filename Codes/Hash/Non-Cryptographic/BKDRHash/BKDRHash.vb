'  Hash function by Brian Kernighan & Dennis Ritchie
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function BKDRHash (key As String) As UInteger
    Dim seed As UInteger = 131
	Dim state As ULong = 0
	Dim i As UInteger = 0

	For i = 0 To key.Length - 1
		state = ((state * seed) + CByte(AscW(key(CInt(i)))) And UInteger.MaxValue)
	Next

	Return state
End Function
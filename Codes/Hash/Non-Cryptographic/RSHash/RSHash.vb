'  Hash function by Robert Sedgwicks
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function RSHash (key As String) As UInteger
    Dim b As UInteger = 378551
	Dim a As ULong = 63689
	Dim state As ULong = 0
	Dim i As UInteger = 0

	For i = 0 To key.Length - 1
		state = (state * a + CByte(AscW(key(CInt(i))))) And UInteger.MaxValue
		a = (a * b) And UInteger.MaxValue
	Next

	Return state
End Function
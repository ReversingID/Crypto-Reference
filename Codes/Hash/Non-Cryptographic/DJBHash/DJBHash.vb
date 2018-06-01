'  Hash function by Daniel J. Bernstein
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function DJBHash (key As String) As UInteger
    Dim state As ULong = 5381
	Dim i As UInteger = 0

	For i = 0 To key.Length - 1
		state = (((state << 5) + state) + CByte(AscW(key(CInt(i)))) And UInteger.MaxValue)
	Next

	Return state
End Function
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function APHash (key As String) As UInteger
    Dim hash As ULong = 0
	Dim i As UInteger = 0

	For i = 0 To str.Length - 1
		hash = ((CByte(AscW(str(CInt(i)))) + (hash << 6) + (hash << 16) - hash) And UInteger.MaxValue)
	Next

	Return hash
End Function
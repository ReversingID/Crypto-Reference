'  Hash function by Justin Sobel
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function JSHash (key As String) As UInteger
    Dim hash As ULong = 1315423911
	Dim i As UInteger = 0

	For i = 0 To key.Length - 1
		hash = ((hash Xor ((hash << 5) + CByte(AscW(key(CInt(i)))) + (hash >> 2))) And UInteger.MaxValue)
	Next

	Return hash
End Function
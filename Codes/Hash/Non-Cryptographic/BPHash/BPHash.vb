'  Hash function by Bruno Preiss
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function BPHash (key As String) As UInteger
    Dim state As UInteger = 0
	Dim i As UInteger = 0

	For i = 0 To key.Length - 1
		state = state << 7 Xor CByte(AscW(key(CInt(i))))
	Next

	Return state
End Function
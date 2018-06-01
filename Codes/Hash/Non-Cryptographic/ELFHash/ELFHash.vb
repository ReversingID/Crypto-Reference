'  Modifikasi PJWHash untuk sistem UNIX.
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function ELFHash (key As String) As UInteger
    Dim state As UInteger = 0
	Dim x As UInteger = 0
	Dim i As UInteger = 0

	For i = 0 To key.Length - 1
		state = (state << 4) + CByte(AscW(key(CInt(i))))
		x = state And &HF0000000UI

		If x <> 0 Then
			state = state Xor (x >> 24)
		End If
		state = state And Not x
	Next

	Return state
End Function
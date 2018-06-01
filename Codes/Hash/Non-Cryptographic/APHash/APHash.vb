'  Hash function by Arash Partow
'  Archive of Reversing.ID
'  Non-Cryptographic Hash
'

' Fungsi ini merupakan method dari sebuah class
Public Shared Function APHash (key As String) As UInteger
    Dim state As ULong = &HAAAAAAAAL
    Dim i As UInteger  = 0

    For i = 0 To key.Length - 1
        state = state Xor If(((i And 1) = 0), 
                 (((state << 7) Xor CByte(AscW(key(CInt(i)))) *   (state >> 3)) And UInteger.MaxValue), 
            ((Not ((state << 11) + (CByte(AscW(key(CInt(i)))) Xor (state >> 5)))) And UInteger.MaxValue))
  	Next

    Return state
End Function
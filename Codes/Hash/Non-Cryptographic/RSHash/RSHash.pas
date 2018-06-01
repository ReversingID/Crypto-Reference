
{
    Hash function by Robert Sedgwicks in C book.
    Archive of Reversing.ID
    Non-Cryptographic Hash
}

function RSHash (const key : String) : Cardinal;
const b = 378551;
var 
    a : Cardinal;
    i : Integer;
begin 
    a      := 63689;
    Result := 0;
    
    for i := 1 to Length(key) do
    begin
        Result := Result * a + Ord(key[i]);
        a      := a * b;
    end;
end;
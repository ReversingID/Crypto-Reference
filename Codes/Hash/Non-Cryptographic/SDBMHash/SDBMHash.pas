{
    Archive of Reversing.ID
    Non-Cryptographic Hash
}
function SDBMHash(const key : String) : Cardinal;
var
    i : Cardinal;
begin
    Result := 0;
    
    for i := 1 to Length(key) do
    begin
        Result := Ord(key[i]) + (Result shl 6) + (Result shl 16) - Result;
    end;
end;
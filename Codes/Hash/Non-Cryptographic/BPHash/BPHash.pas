{
    Hash function by Bruno Preiss
    Archive of Reversing.ID
    Non-Cryptographic Hash
}
function BPHash(const key : String) : Cardinal;
var
    i : Cardinal;
begin
    Result := 0;

    for i := 1 to Length(key) do
    begin
        Result := Result shl 7 xor Ord(key[i]);
    end;
end;
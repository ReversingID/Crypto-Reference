{
    Hash function by Donald E. Knuth
    Archive of Reversing.ID
    Non-Cryptographic Hash
}
function DEKHash(const key : String) : Cardinal;
var
    i : Cardinal;
begin
    Result := Length(key);

    for i := 1 to Length(key) do
    begin
        Result := ((Result shr 5) xor (Result shl 27)) xor Ord(key[i]);
    end;
end;
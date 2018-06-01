{
    Hash function by Daniel J. Bernstein
    Archive of Reversing.ID
    Non-Cryptographic Hash
}
function DJBHash(const key : String) : Cardinal;
var
    i : Cardinal;
begin
    Result := 5381;

    for i := 1 to Length(key) do
    begin
        Result := ((Result shl 5) + Result) + Ord(key[i]);
    end;
end;
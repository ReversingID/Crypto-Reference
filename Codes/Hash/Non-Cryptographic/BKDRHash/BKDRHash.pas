{
    Hash function by Brian Kernighan & Dennis Ritchie
    Archive of Reversing.ID
    Non-Cryptographic Hash
}
function BKDRHash(const key : String) : Cardinal;
const seed = 131; (* 31 131 1313 13131 131313 etc... *)
var
    i : Cardinal;
begin
    Result := 0;

    for i := 1 to Length(key) do
    begin
        Result := (Result * seed) + Ord(key[i]);
    end;
end;
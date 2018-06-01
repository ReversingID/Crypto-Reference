{
    Hash function by Peter J. Weinberger
    Archive of Reversing.ID
    Non-Cryptographic Hash
}
function PJWHash(const key : String) : Cardinal;
const BitsInCardinal = Sizeof(Cardinal) * 8;
const ThreeQuarters  = (BitsInCardinal  * 3) div 4;
const OneEighth      = BitsInCardinal div 8;
const HighBits       : Cardinal = (not Cardinal(0)) shl (BitsInCardinal - OneEighth);
var
    i    : Cardinal;
    Test : Cardinal;
begin
    Result := 0;
    
    for i := 1 to Length(key) do
    begin
        Result := (Result shl OneEighth) + Ord(key[i]);
        Test   := Result and HighBits;
        If (Test <> 0) then
        begin
            Result := (Result xor (Test shr ThreeQuarters)) and (not HighBits);
        end;
    end;
end;
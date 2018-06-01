{
    Modifikasi PJWHash untuk sistem UNIX.
    Archive of Reversing.ID
    Non-Cryptographic Hash
}
function ELFHash(const key : String) : Cardinal;
var
    i : Cardinal;
    x : Cardinal;
begin
    Result := 0;
    
    for i := 1 to Length(key) do
    begin
        Result := (Result shl 4) + Ord(key[i]);
        x      := Result and $F0000000;
        if (x <> 0) then
        begin
            Result := Result xor (x shr 24);
        end;
            Result := Result and (not x);
    end;
end;
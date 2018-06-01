{
    Hash function by Justin Sobel
    Archive of Reversing.ID
    Non-Cryptographic Hash
}

function JSHash(const key : String) : Cardinal;
var
  i : Integer;
begin
    Result := 1315423911;

    for i := 1 to Length(key) do
    begin
        Result := Result xor ((Result shl 5) + Ord(key[i]) + (Result shr 2));
    end;
end;
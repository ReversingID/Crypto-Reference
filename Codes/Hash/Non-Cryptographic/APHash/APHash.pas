{
	Hash function by Arash Partow
    Archive of Reversing.ID
    Non-Cryptographic Hash
}

function APHash (const key : String) : Cardinal;
var 
    i : Cardinal;
begin 
    Result := $AAAAAAAA;

    for i := 1 to Length(key) do 
    begin 
        if ((i - 1) and 1) = 0 then 
            Result := Result xor ((Result shl 7) xor Ord(key[i]) * Result shr 3)
        else 
            Result := Result xor (not((Result shl 11) + Ord(key[i]) xor (Result shr 5)));
    end;
end;
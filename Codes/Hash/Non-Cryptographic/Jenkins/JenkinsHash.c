/*
	Hash function by Bob Jenkins
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o JenkinsHash.asm JenkinsHash.c

        (msvc)
        $ cl /c /FaAPHash.asm JenkinsHash.c
*/
#include <stdint.h>

// proses mix, dibutuhkan oleh lookup2
#define mix2(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

// proses mix, dibutuhkan oleh lookup3
#define rot(x, k)   (((x)<<(k)) | ((x)>>(32-(k))))
#define mix3(a,b,c) \
{ \
  a -= c;  a ^= rot(c, 4);  c += b; \
  b -= a;  b ^= rot(a, 6);  a += c; \
  c -= b;  c ^= rot(b, 8);  b += a; \
  a -= c;  a ^= rot(c,16);  c += b; \
  b -= a;  b ^= rot(a,19);  a += c; \
  c -= b;  c ^= rot(b, 4);  b += a; \
}
#define finalmix(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c,4);  \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}

//------------------------------------------------------------------------------------------

// Jenkins one at a time
// diadaptasi dari halaman Bob Jenkins
uint32_t JenkinsHash_one_at_a_time(const char* key, uint32_t length)
{
    uint32_t i;
    uint32_t state = 0;

    for (i = 0; i < length; i++)
    {
        state += key[i];
        state += state << 10;
        state ^= state >> 6;
    }

    state += state << 3;
    state ^= state >> 11;
    state += state << 15;
    
    return state;
}

//------------------------------------------------------------------------------------------

// Jenkins Lookup 2
uint32_t JenkinsHash_loopup2(const char* key, uint32_t length, uint32_t initval)
{
    uint32_t a, b, c, len;

    // Setup internal state
    len = length;
    a = b = 0x9e3779b9;     // golden ratio
    c = initval;            // IV: 0 atau bisa sembarang nilai

    // Menangani sebagian besar data -------------------------------
    while (len >= 12)
    {
        a += (key[0] +((uint32_t)key[1]<<8) +((uint32_t)key[2]<<16) +((uint32_t)key[3]<<24));
        b += (key[4] +((uint32_t)key[5]<<8) +((uint32_t)key[6]<<16) +((uint32_t)key[7]<<24));
        c += (key[8] +((uint32_t)key[9]<<8) +((uint32_t)key[10]<<16)+((uint32_t)key[11]<<24));
        mix2(a,b,c);
        key += 12; len -= 12;
    }

    // Menangani 11 byte terakhir
    c += length;
    
    switch(len)
    {
    case 11: c+=((uint32_t)key[10]<<24);
    case 10: c+=((uint32_t)key[9]<<16);
    case 9 : c+=((uint32_t)key[8]<<8);
        // byte pertama c untuk menyimpan length
    case 8 : b+=((uint32_t)key[7]<<24);
    case 7 : b+=((uint32_t)key[6]<<16);
    case 6 : b+=((uint32_t)key[5]<<8);
    case 5 : b+=key[4];
    case 4 : a+=((uint32_t)key[3]<<24);
    case 3 : a+=((uint32_t)key[2]<<16);
    case 2 : a+=((uint32_t)key[1]<<8);
    case 1 : a+=key[0];
        // case 0: tak ada yang perlu ditambah
    }
    mix2(a,b,c);

    return c;
}

//------------------------------------------------------------------------------------------

// Jenkins Lookup 3
uint32_t JenkinsHash_loopup3(const uint32_t* key, uint32_t length, uint32_t initval)
{
    uint32_t a, b, c;

    // Setup internal state
    // IV: 0 atau bisa sembarang nilai
    a = b = c = 0xDEADBEEF + (((uint32_t)length)<<2) + initval;

    // Menangani sebagian besar data -------------------------------
    while (length > 3)
    {
        a += key[0];
        b += key[1];
        c += key[2];
        mix3(a,b,c);
        length -= 3;
        key += 3;
    }

    // Menangani 3 data terakhir
    switch (length)
    {
        case 3: c += key[2];
        case 2: b += key[1];
        case 1: a += key[0];
            finalmix(a,b,c);
        // case 0: tak ada yang perlu ditambah
    }
    mix2(a,b,c);

    return c;
}
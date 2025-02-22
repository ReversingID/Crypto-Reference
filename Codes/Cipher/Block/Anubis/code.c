/*
    Anubis by Vincent Rijmen, Paulo S. L. M. Barreto
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc)
    $ cl code.c

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o code.asm code.c

    (msvc)
    $ cl /c /FaBBS.asm code.c
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16
#define MIN_N           4
#define MAX_N           10
#define MIN_ROUNDS      (8 + MIN_N)
#define MAX_ROUNDS      (8 + MAX_N)
#define MIN_KEYSIZEB    (4 * MIN_N)
#define MAX_KEYSIZEB    (4 * MAX_N)

/** Lookup Table **/
static const uint32_t T0[256] = {
    0xA753A6F5U, 0xD3BB6BD0U, 0xE6D1BF6EU, 0x71E2D93BU,
    0xD0BD67DAU, 0xAC458ACFU, 0x4D9A29B3U, 0x79F2F90BU,
    0x3A74E89CU, 0xC98F038CU, 0x913F7E41U, 0xFCE5D732U,
    0x1E3C7844U, 0x478E018FU, 0x54A84DE5U, 0xBD67CEA9U,
    0x8C050A0FU, 0xA557AEF9U, 0x7AF4F501U, 0xFBEBCB20U,
    0x63C69157U, 0xB86DDAB7U, 0xDDA753F4U, 0xD4B577C2U,
    0xE5D7B364U, 0xB37BF68DU, 0xC59733A4U, 0xBE61C2A3U,
    0xA94F9ED1U, 0x880D1A17U, 0x0C183028U, 0xA259B2EBU,
    0x3972E496U, 0xDFA35BF8U, 0x2952A4F6U, 0xDAA94FE6U,
    0x2B56ACFAU, 0xA84D9AD7U, 0xCB8B0B80U, 0x4C982DB5U,
    0x4B9631A7U, 0x224488CCU, 0xAA4992DBU, 0x244890D8U,
    0x4182199BU, 0x70E0DD3DU, 0xA651A2F3U, 0xF9EFC32CU,
    0x5AB475C1U, 0xE2D9AF76U, 0xB07DFA87U, 0x366CD8B4U,
    0x7DFAE913U, 0xE4D5B762U, 0x3366CCAAU, 0xFFE3DB38U,
    0x60C09D5DU, 0x204080C0U, 0x08102030U, 0x8B0B161DU,
    0x5EBC65D9U, 0xAB4B96DDU, 0x7FFEE11FU, 0x78F0FD0DU,
    0x7CF8ED15U, 0x2C58B0E8U, 0x57AE41EFU, 0xD2B96FD6U,
    0xDCA557F2U, 0x6DDAA973U, 0x7EFCE519U, 0x0D1A342EU,
    0x53A651F7U, 0x94356A5FU, 0xC39B2BB0U, 0x2850A0F0U,
    0x274E9CD2U, 0x060C1814U, 0x5FBE61DFU, 0xAD478EC9U,
    0x67CE814FU, 0x5CB86DD5U, 0x55AA49E3U, 0x48903DADU,
    0x0E1C3824U, 0x52A455F1U, 0xEAC98F46U, 0x42841591U,
    0x5BB671C7U, 0x5DBA69D3U, 0x3060C0A0U, 0x58B07DCDU,
    0x51A259FBU, 0x59B279CBU, 0x3C78F088U, 0x4E9C25B9U,
    0x3870E090U, 0x8A09121BU, 0x72E4D531U, 0x14285078U,
    0xE7D3BB68U, 0xC6913FAEU, 0xDEA15FFEU, 0x50A05DFDU,
    0x8E010203U, 0x9239724BU, 0xD1BF63DCU, 0x77EEC12FU,
    0x933B764DU, 0x458A0983U, 0x9A29527BU, 0xCE811F9EU,
    0x2D5AB4EEU, 0x03060C0AU, 0x62C49551U, 0xB671E293U,
    0xB96FDEB1U, 0xBF63C6A5U, 0x96316253U, 0x6BD6B167U,
    0x3F7EFC82U, 0x070E1C12U, 0x1224486CU, 0xAE4182C3U,
    0x40801D9DU, 0x3468D0B8U, 0x468C0589U, 0x3E7CF884U,
    0xDBAB4BE0U, 0xCF831B98U, 0xECC59752U, 0xCC851792U,
    0xC19F23BCU, 0xA15FBEE1U, 0xC09D27BAU, 0xD6B17FCEU,
    0x1D3A744EU, 0xF4F5F702U, 0x61C2995BU, 0x3B76EC9AU,
    0x10204060U, 0xD8AD47EAU, 0x68D0BD6DU, 0xA05DBAE7U,
    0xB17FFE81U, 0x0A14283CU, 0x69D2B96BU, 0x6CD8AD75U,
    0x499239ABU, 0xFAE9CF26U, 0x76ECC529U, 0xC49537A2U,
    0x9E214263U, 0x9B2B567DU, 0x6EDCA579U, 0x992F5E71U,
    0xC2992FB6U, 0xB773E695U, 0x982D5A77U, 0xBC65CAAFU,
    0x8F030605U, 0x85172E39U, 0x1F3E7C42U, 0xB475EA9FU,
    0xF8EDC72AU, 0x11224466U, 0x2E5CB8E4U, 0x00000000U,
    0x254A94DEU, 0x1C387048U, 0x2A54A8FCU, 0x3D7AF48EU,
    0x050A141EU, 0x4F9E21BFU, 0x7BF6F107U, 0xB279F28BU,
    0x3264C8ACU, 0x903D7A47U, 0xAF4386C5U, 0x19326456U,
    0xA35BB6EDU, 0xF7F3FB08U, 0x73E6D137U, 0x9D274E69U,
    0x152A547EU, 0x74E8CD25U, 0xEEC19F5EU, 0xCA890F86U,
    0x9F234665U, 0x0F1E3C22U, 0x1B366C5AU, 0x75EAC923U,
    0x86112233U, 0x84152A3FU, 0x9C254A6FU, 0x4A9435A1U,
    0x97336655U, 0x1A34685CU, 0x65CA8943U, 0xF6F1FF0EU,
    0xEDC79354U, 0x09122436U, 0xBB6BD6BDU, 0x264C98D4U,
    0x831B362DU, 0xEBCB8B40U, 0x6FDEA17FU, 0x811F3E21U,
    0x04081018U, 0x6AD4B561U, 0x43861197U, 0x01020406U,
    0x172E5C72U, 0xE1DFA37CU, 0x87132635U, 0xF5F7F304U,
    0x8D070E09U, 0xE3DBAB70U, 0x23468CCAU, 0x801D3A27U,
    0x44880D85U, 0x162C5874U, 0x66CC8549U, 0x214284C6U,
    0xFEE1DF3EU, 0xD5B773C4U, 0x3162C4A6U, 0xD9AF43ECU,
    0x356AD4BEU, 0x18306050U, 0x0204080CU, 0x64C88D45U,
    0xF2F9EF16U, 0xF1FFE31CU, 0x56AC45E9U, 0xCD871394U,
    0x8219322BU, 0xC88D078AU, 0xBA69D2BBU, 0xF0FDE71AU,
    0xEFC39B58U, 0xE9CF834CU, 0xE8CD874AU, 0xFDE7D334U,
    0x890F1E11U, 0xD7B37BC8U, 0xC7933BA8U, 0xB577EE99U,
    0xA455AAFFU, 0x2F5EBCE2U, 0x95376E59U, 0x13264C6AU,
    0x0B162C3AU, 0xF3FBEB10U, 0xE0DDA77AU, 0x376EDCB2U,
};

static const uint32_t T1[256] = {
    0x53A7F5A6U, 0xBBD3D06BU, 0xD1E66EBFU, 0xE2713BD9U,
    0xBDD0DA67U, 0x45ACCF8AU, 0x9A4DB329U, 0xF2790BF9U,
    0x743A9CE8U, 0x8FC98C03U, 0x3F91417EU, 0xE5FC32D7U,
    0x3C1E4478U, 0x8E478F01U, 0xA854E54DU, 0x67BDA9CEU,
    0x058C0F0AU, 0x57A5F9AEU, 0xF47A01F5U, 0xEBFB20CBU,
    0xC6635791U, 0x6DB8B7DAU, 0xA7DDF453U, 0xB5D4C277U,
    0xD7E564B3U, 0x7BB38DF6U, 0x97C5A433U, 0x61BEA3C2U,
    0x4FA9D19EU, 0x0D88171AU, 0x180C2830U, 0x59A2EBB2U,
    0x723996E4U, 0xA3DFF85BU, 0x5229F6A4U, 0xA9DAE64FU,
    0x562BFAACU, 0x4DA8D79AU, 0x8BCB800BU, 0x984CB52DU,
    0x964BA731U, 0x4422CC88U, 0x49AADB92U, 0x4824D890U,
    0x82419B19U, 0xE0703DDDU, 0x51A6F3A2U, 0xEFF92CC3U,
    0xB45AC175U, 0xD9E276AFU, 0x7DB087FAU, 0x6C36B4D8U,
    0xFA7D13E9U, 0xD5E462B7U, 0x6633AACCU, 0xE3FF38DBU,
    0xC0605D9DU, 0x4020C080U, 0x10083020U, 0x0B8B1D16U,
    0xBC5ED965U, 0x4BABDD96U, 0xFE7F1FE1U, 0xF0780DFDU,
    0xF87C15EDU, 0x582CE8B0U, 0xAE57EF41U, 0xB9D2D66FU,
    0xA5DCF257U, 0xDA6D73A9U, 0xFC7E19E5U, 0x1A0D2E34U,
    0xA653F751U, 0x35945F6AU, 0x9BC3B02BU, 0x5028F0A0U,
    0x4E27D29CU, 0x0C061418U, 0xBE5FDF61U, 0x47ADC98EU,
    0xCE674F81U, 0xB85CD56DU, 0xAA55E349U, 0x9048AD3DU,
    0x1C0E2438U, 0xA452F155U, 0xC9EA468FU, 0x84429115U,
    0xB65BC771U, 0xBA5DD369U, 0x6030A0C0U, 0xB058CD7DU,
    0xA251FB59U, 0xB259CB79U, 0x783C88F0U, 0x9C4EB925U,
    0x703890E0U, 0x098A1B12U, 0xE47231D5U, 0x28147850U,
    0xD3E768BBU, 0x91C6AE3FU, 0xA1DEFE5FU, 0xA050FD5DU,
    0x018E0302U, 0x39924B72U, 0xBFD1DC63U, 0xEE772FC1U,
    0x3B934D76U, 0x8A458309U, 0x299A7B52U, 0x81CE9E1FU,
    0x5A2DEEB4U, 0x06030A0CU, 0xC4625195U, 0x71B693E2U,
    0x6FB9B1DEU, 0x63BFA5C6U, 0x31965362U, 0xD66B67B1U,
    0x7E3F82FCU, 0x0E07121CU, 0x24126C48U, 0x41AEC382U,
    0x80409D1DU, 0x6834B8D0U, 0x8C468905U, 0x7C3E84F8U,
    0xABDBE04BU, 0x83CF981BU, 0xC5EC5297U, 0x85CC9217U,
    0x9FC1BC23U, 0x5FA1E1BEU, 0x9DC0BA27U, 0xB1D6CE7FU,
    0x3A1D4E74U, 0xF5F402F7U, 0xC2615B99U, 0x763B9AECU,
    0x20106040U, 0xADD8EA47U, 0xD0686DBDU, 0x5DA0E7BAU,
    0x7FB181FEU, 0x140A3C28U, 0xD2696BB9U, 0xD86C75ADU,
    0x9249AB39U, 0xE9FA26CFU, 0xEC7629C5U, 0x95C4A237U,
    0x219E6342U, 0x2B9B7D56U, 0xDC6E79A5U, 0x2F99715EU,
    0x99C2B62FU, 0x73B795E6U, 0x2D98775AU, 0x65BCAFCAU,
    0x038F0506U, 0x1785392EU, 0x3E1F427CU, 0x75B49FEAU,
    0xEDF82AC7U, 0x22116644U, 0x5C2EE4B8U, 0x00000000U,
    0x4A25DE94U, 0x381C4870U, 0x542AFCA8U, 0x7A3D8EF4U,
    0x0A051E14U, 0x9E4FBF21U, 0xF67B07F1U, 0x79B28BF2U,
    0x6432ACC8U, 0x3D90477AU, 0x43AFC586U, 0x32195664U,
    0x5BA3EDB6U, 0xF3F708FBU, 0xE67337D1U, 0x279D694EU,
    0x2A157E54U, 0xE87425CDU, 0xC1EE5E9FU, 0x89CA860FU,
    0x239F6546U, 0x1E0F223CU, 0x361B5A6CU, 0xEA7523C9U,
    0x11863322U, 0x15843F2AU, 0x259C6F4AU, 0x944AA135U,
    0x33975566U, 0x341A5C68U, 0xCA654389U, 0xF1F60EFFU,
    0xC7ED5493U, 0x12093624U, 0x6BBBBDD6U, 0x4C26D498U,
    0x1B832D36U, 0xCBEB408BU, 0xDE6F7FA1U, 0x1F81213EU,
    0x08041810U, 0xD46A61B5U, 0x86439711U, 0x02010604U,
    0x2E17725CU, 0xDFE17CA3U, 0x13873526U, 0xF7F504F3U,
    0x078D090EU, 0xDBE370ABU, 0x4623CA8CU, 0x1D80273AU,
    0x8844850DU, 0x2C167458U, 0xCC664985U, 0x4221C684U,
    0xE1FE3EDFU, 0xB7D5C473U, 0x6231A6C4U, 0xAFD9EC43U,
    0x6A35BED4U, 0x30185060U, 0x04020C08U, 0xC864458DU,
    0xF9F216EFU, 0xFFF11CE3U, 0xAC56E945U, 0x87CD9413U,
    0x19822B32U, 0x8DC88A07U, 0x69BABBD2U, 0xFDF01AE7U,
    0xC3EF589BU, 0xCFE94C83U, 0xCDE84A87U, 0xE7FD34D3U,
    0x0F89111EU, 0xB3D7C87BU, 0x93C7A83BU, 0x77B599EEU,
    0x55A4FFAAU, 0x5E2FE2BCU, 0x3795596EU, 0x26136A4CU,
    0x160B3A2CU, 0xFBF310EBU, 0xDDE07AA7U, 0x6E37B2DCU,
};

static const uint32_t T2[256] = {
    0xA6F5A753U, 0x6BD0D3BBU, 0xBF6EE6D1U, 0xD93B71E2U,
    0x67DAD0BDU, 0x8ACFAC45U, 0x29B34D9AU, 0xF90B79F2U,
    0xE89C3A74U, 0x038CC98FU, 0x7E41913FU, 0xD732FCE5U,
    0x78441E3CU, 0x018F478EU, 0x4DE554A8U, 0xCEA9BD67U,
    0x0A0F8C05U, 0xAEF9A557U, 0xF5017AF4U, 0xCB20FBEBU,
    0x915763C6U, 0xDAB7B86DU, 0x53F4DDA7U, 0x77C2D4B5U,
    0xB364E5D7U, 0xF68DB37BU, 0x33A4C597U, 0xC2A3BE61U,
    0x9ED1A94FU, 0x1A17880DU, 0x30280C18U, 0xB2EBA259U,
    0xE4963972U, 0x5BF8DFA3U, 0xA4F62952U, 0x4FE6DAA9U,
    0xACFA2B56U, 0x9AD7A84DU, 0x0B80CB8BU, 0x2DB54C98U,
    0x31A74B96U, 0x88CC2244U, 0x92DBAA49U, 0x90D82448U,
    0x199B4182U, 0xDD3D70E0U, 0xA2F3A651U, 0xC32CF9EFU,
    0x75C15AB4U, 0xAF76E2D9U, 0xFA87B07DU, 0xD8B4366CU,
    0xE9137DFAU, 0xB762E4D5U, 0xCCAA3366U, 0xDB38FFE3U,
    0x9D5D60C0U, 0x80C02040U, 0x20300810U, 0x161D8B0BU,
    0x65D95EBCU, 0x96DDAB4BU, 0xE11F7FFEU, 0xFD0D78F0U,
    0xED157CF8U, 0xB0E82C58U, 0x41EF57AEU, 0x6FD6D2B9U,
    0x57F2DCA5U, 0xA9736DDAU, 0xE5197EFCU, 0x342E0D1AU,
    0x51F753A6U, 0x6A5F9435U, 0x2BB0C39BU, 0xA0F02850U,
    0x9CD2274EU, 0x1814060CU, 0x61DF5FBEU, 0x8EC9AD47U,
    0x814F67CEU, 0x6DD55CB8U, 0x49E355AAU, 0x3DAD4890U,
    0x38240E1CU, 0x55F152A4U, 0x8F46EAC9U, 0x15914284U,
    0x71C75BB6U, 0x69D35DBAU, 0xC0A03060U, 0x7DCD58B0U,
    0x59FB51A2U, 0x79CB59B2U, 0xF0883C78U, 0x25B94E9CU,
    0xE0903870U, 0x121B8A09U, 0xD53172E4U, 0x50781428U,
    0xBB68E7D3U, 0x3FAEC691U, 0x5FFEDEA1U, 0x5DFD50A0U,
    0x02038E01U, 0x724B9239U, 0x63DCD1BFU, 0xC12F77EEU,
    0x764D933BU, 0x0983458AU, 0x527B9A29U, 0x1F9ECE81U,
    0xB4EE2D5AU, 0x0C0A0306U, 0x955162C4U, 0xE293B671U,
    0xDEB1B96FU, 0xC6A5BF63U, 0x62539631U, 0xB1676BD6U,
    0xFC823F7EU, 0x1C12070EU, 0x486C1224U, 0x82C3AE41U,
    0x1D9D4080U, 0xD0B83468U, 0x0589468CU, 0xF8843E7CU,
    0x4BE0DBABU, 0x1B98CF83U, 0x9752ECC5U, 0x1792CC85U,
    0x23BCC19FU, 0xBEE1A15FU, 0x27BAC09DU, 0x7FCED6B1U,
    0x744E1D3AU, 0xF702F4F5U, 0x995B61C2U, 0xEC9A3B76U,
    0x40601020U, 0x47EAD8ADU, 0xBD6D68D0U, 0xBAE7A05DU,
    0xFE81B17FU, 0x283C0A14U, 0xB96B69D2U, 0xAD756CD8U,
    0x39AB4992U, 0xCF26FAE9U, 0xC52976ECU, 0x37A2C495U,
    0x42639E21U, 0x567D9B2BU, 0xA5796EDCU, 0x5E71992FU,
    0x2FB6C299U, 0xE695B773U, 0x5A77982DU, 0xCAAFBC65U,
    0x06058F03U, 0x2E398517U, 0x7C421F3EU, 0xEA9FB475U,
    0xC72AF8EDU, 0x44661122U, 0xB8E42E5CU, 0x00000000U,
    0x94DE254AU, 0x70481C38U, 0xA8FC2A54U, 0xF48E3D7AU,
    0x141E050AU, 0x21BF4F9EU, 0xF1077BF6U, 0xF28BB279U,
    0xC8AC3264U, 0x7A47903DU, 0x86C5AF43U, 0x64561932U,
    0xB6EDA35BU, 0xFB08F7F3U, 0xD13773E6U, 0x4E699D27U,
    0x547E152AU, 0xCD2574E8U, 0x9F5EEEC1U, 0x0F86CA89U,
    0x46659F23U, 0x3C220F1EU, 0x6C5A1B36U, 0xC92375EAU,
    0x22338611U, 0x2A3F8415U, 0x4A6F9C25U, 0x35A14A94U,
    0x66559733U, 0x685C1A34U, 0x894365CAU, 0xFF0EF6F1U,
    0x9354EDC7U, 0x24360912U, 0xD6BDBB6BU, 0x98D4264CU,
    0x362D831BU, 0x8B40EBCBU, 0xA17F6FDEU, 0x3E21811FU,
    0x10180408U, 0xB5616AD4U, 0x11974386U, 0x04060102U,
    0x5C72172EU, 0xA37CE1DFU, 0x26358713U, 0xF304F5F7U,
    0x0E098D07U, 0xAB70E3DBU, 0x8CCA2346U, 0x3A27801DU,
    0x0D854488U, 0x5874162CU, 0x854966CCU, 0x84C62142U,
    0xDF3EFEE1U, 0x73C4D5B7U, 0xC4A63162U, 0x43ECD9AFU,
    0xD4BE356AU, 0x60501830U, 0x080C0204U, 0x8D4564C8U,
    0xEF16F2F9U, 0xE31CF1FFU, 0x45E956ACU, 0x1394CD87U,
    0x322B8219U, 0x078AC88DU, 0xD2BBBA69U, 0xE71AF0FDU,
    0x9B58EFC3U, 0x834CE9CFU, 0x874AE8CDU, 0xD334FDE7U,
    0x1E11890FU, 0x7BC8D7B3U, 0x3BA8C793U, 0xEE99B577U,
    0xAAFFA455U, 0xBCE22F5EU, 0x6E599537U, 0x4C6A1326U,
    0x2C3A0B16U, 0xEB10F3FBU, 0xA77AE0DDU, 0xDCB2376EU,
};

static const uint32_t T3[256] = {
    0xF5A653A7U, 0xD06BBBD3U, 0x6EBFD1E6U, 0x3BD9E271U,
    0xDA67BDD0U, 0xCF8A45ACU, 0xB3299A4DU, 0x0BF9F279U,
    0x9CE8743AU, 0x8C038FC9U, 0x417E3F91U, 0x32D7E5FCU,
    0x44783C1EU, 0x8F018E47U, 0xE54DA854U, 0xA9CE67BDU,
    0x0F0A058CU, 0xF9AE57A5U, 0x01F5F47AU, 0x20CBEBFBU,
    0x5791C663U, 0xB7DA6DB8U, 0xF453A7DDU, 0xC277B5D4U,
    0x64B3D7E5U, 0x8DF67BB3U, 0xA43397C5U, 0xA3C261BEU,
    0xD19E4FA9U, 0x171A0D88U, 0x2830180CU, 0xEBB259A2U,
    0x96E47239U, 0xF85BA3DFU, 0xF6A45229U, 0xE64FA9DAU,
    0xFAAC562BU, 0xD79A4DA8U, 0x800B8BCBU, 0xB52D984CU,
    0xA731964BU, 0xCC884422U, 0xDB9249AAU, 0xD8904824U,
    0x9B198241U, 0x3DDDE070U, 0xF3A251A6U, 0x2CC3EFF9U,
    0xC175B45AU, 0x76AFD9E2U, 0x87FA7DB0U, 0xB4D86C36U,
    0x13E9FA7DU, 0x62B7D5E4U, 0xAACC6633U, 0x38DBE3FFU,
    0x5D9DC060U, 0xC0804020U, 0x30201008U, 0x1D160B8BU,
    0xD965BC5EU, 0xDD964BABU, 0x1FE1FE7FU, 0x0DFDF078U,
    0x15EDF87CU, 0xE8B0582CU, 0xEF41AE57U, 0xD66FB9D2U,
    0xF257A5DCU, 0x73A9DA6DU, 0x19E5FC7EU, 0x2E341A0DU,
    0xF751A653U, 0x5F6A3594U, 0xB02B9BC3U, 0xF0A05028U,
    0xD29C4E27U, 0x14180C06U, 0xDF61BE5FU, 0xC98E47ADU,
    0x4F81CE67U, 0xD56DB85CU, 0xE349AA55U, 0xAD3D9048U,
    0x24381C0EU, 0xF155A452U, 0x468FC9EAU, 0x91158442U,
    0xC771B65BU, 0xD369BA5DU, 0xA0C06030U, 0xCD7DB058U,
    0xFB59A251U, 0xCB79B259U, 0x88F0783CU, 0xB9259C4EU,
    0x90E07038U, 0x1B12098AU, 0x31D5E472U, 0x78502814U,
    0x68BBD3E7U, 0xAE3F91C6U, 0xFE5FA1DEU, 0xFD5DA050U,
    0x0302018EU, 0x4B723992U, 0xDC63BFD1U, 0x2FC1EE77U,
    0x4D763B93U, 0x83098A45U, 0x7B52299AU, 0x9E1F81CEU,
    0xEEB45A2DU, 0x0A0C0603U, 0x5195C462U, 0x93E271B6U,
    0xB1DE6FB9U, 0xA5C663BFU, 0x53623196U, 0x67B1D66BU,
    0x82FC7E3FU, 0x121C0E07U, 0x6C482412U, 0xC38241AEU,
    0x9D1D8040U, 0xB8D06834U, 0x89058C46U, 0x84F87C3EU,
    0xE04BABDBU, 0x981B83CFU, 0x5297C5ECU, 0x921785CCU,
    0xBC239FC1U, 0xE1BE5FA1U, 0xBA279DC0U, 0xCE7FB1D6U,
    0x4E743A1DU, 0x02F7F5F4U, 0x5B99C261U, 0x9AEC763BU,
    0x60402010U, 0xEA47ADD8U, 0x6DBDD068U, 0xE7BA5DA0U,
    0x81FE7FB1U, 0x3C28140AU, 0x6BB9D269U, 0x75ADD86CU,
    0xAB399249U, 0x26CFE9FAU, 0x29C5EC76U, 0xA23795C4U,
    0x6342219EU, 0x7D562B9BU, 0x79A5DC6EU, 0x715E2F99U,
    0xB62F99C2U, 0x95E673B7U, 0x775A2D98U, 0xAFCA65BCU,
    0x0506038FU, 0x392E1785U, 0x427C3E1FU, 0x9FEA75B4U,
    0x2AC7EDF8U, 0x66442211U, 0xE4B85C2EU, 0x00000000U,
    0xDE944A25U, 0x4870381CU, 0xFCA8542AU, 0x8EF47A3DU,
    0x1E140A05U, 0xBF219E4FU, 0x07F1F67BU, 0x8BF279B2U,
    0xACC86432U, 0x477A3D90U, 0xC58643AFU, 0x56643219U,
    0xEDB65BA3U, 0x08FBF3F7U, 0x37D1E673U, 0x694E279DU,
    0x7E542A15U, 0x25CDE874U, 0x5E9FC1EEU, 0x860F89CAU,
    0x6546239FU, 0x223C1E0FU, 0x5A6C361BU, 0x23C9EA75U,
    0x33221186U, 0x3F2A1584U, 0x6F4A259CU, 0xA135944AU,
    0x55663397U, 0x5C68341AU, 0x4389CA65U, 0x0EFFF1F6U,
    0x5493C7EDU, 0x36241209U, 0xBDD66BBBU, 0xD4984C26U,
    0x2D361B83U, 0x408BCBEBU, 0x7FA1DE6FU, 0x213E1F81U,
    0x18100804U, 0x61B5D46AU, 0x97118643U, 0x06040201U,
    0x725C2E17U, 0x7CA3DFE1U, 0x35261387U, 0x04F3F7F5U,
    0x090E078DU, 0x70ABDBE3U, 0xCA8C4623U, 0x273A1D80U,
    0x850D8844U, 0x74582C16U, 0x4985CC66U, 0xC6844221U,
    0x3EDFE1FEU, 0xC473B7D5U, 0xA6C46231U, 0xEC43AFD9U,
    0xBED46A35U, 0x50603018U, 0x0C080402U, 0x458DC864U,
    0x16EFF9F2U, 0x1CE3FFF1U, 0xE945AC56U, 0x941387CDU,
    0x2B321982U, 0x8A078DC8U, 0xBBD269BAU, 0x1AE7FDF0U,
    0x589BC3EFU, 0x4C83CFE9U, 0x4A87CDE8U, 0x34D3E7FDU,
    0x111E0F89U, 0xC87BB3D7U, 0xA83B93C7U, 0x99EE77B5U,
    0xFFAA55A4U, 0xE2BC5E2FU, 0x596E3795U, 0x6A4C2613U,
    0x3A2C160BU, 0x10EBFBF3U, 0x7AA7DDE0U, 0xB2DC6E37U,
};

static const uint32_t T4[256] = {
    0xA7A7A7A7U, 0xD3D3D3D3U, 0xE6E6E6E6U, 0x71717171U,
    0xD0D0D0D0U, 0xACACACACU, 0x4D4D4D4DU, 0x79797979U,
    0x3A3A3A3AU, 0xC9C9C9C9U, 0x91919191U, 0xFCFCFCFCU,
    0x1E1E1E1EU, 0x47474747U, 0x54545454U, 0xBDBDBDBDU,
    0x8C8C8C8CU, 0xA5A5A5A5U, 0x7A7A7A7AU, 0xFBFBFBFBU,
    0x63636363U, 0xB8B8B8B8U, 0xDDDDDDDDU, 0xD4D4D4D4U,
    0xE5E5E5E5U, 0xB3B3B3B3U, 0xC5C5C5C5U, 0xBEBEBEBEU,
    0xA9A9A9A9U, 0x88888888U, 0x0C0C0C0CU, 0xA2A2A2A2U,
    0x39393939U, 0xDFDFDFDFU, 0x29292929U, 0xDADADADAU,
    0x2B2B2B2BU, 0xA8A8A8A8U, 0xCBCBCBCBU, 0x4C4C4C4CU,
    0x4B4B4B4BU, 0x22222222U, 0xAAAAAAAAU, 0x24242424U,
    0x41414141U, 0x70707070U, 0xA6A6A6A6U, 0xF9F9F9F9U,
    0x5A5A5A5AU, 0xE2E2E2E2U, 0xB0B0B0B0U, 0x36363636U,
    0x7D7D7D7DU, 0xE4E4E4E4U, 0x33333333U, 0xFFFFFFFFU,
    0x60606060U, 0x20202020U, 0x08080808U, 0x8B8B8B8BU,
    0x5E5E5E5EU, 0xABABABABU, 0x7F7F7F7FU, 0x78787878U,
    0x7C7C7C7CU, 0x2C2C2C2CU, 0x57575757U, 0xD2D2D2D2U,
    0xDCDCDCDCU, 0x6D6D6D6DU, 0x7E7E7E7EU, 0x0D0D0D0DU,
    0x53535353U, 0x94949494U, 0xC3C3C3C3U, 0x28282828U,
    0x27272727U, 0x06060606U, 0x5F5F5F5FU, 0xADADADADU,
    0x67676767U, 0x5C5C5C5CU, 0x55555555U, 0x48484848U,
    0x0E0E0E0EU, 0x52525252U, 0xEAEAEAEAU, 0x42424242U,
    0x5B5B5B5BU, 0x5D5D5D5DU, 0x30303030U, 0x58585858U,
    0x51515151U, 0x59595959U, 0x3C3C3C3CU, 0x4E4E4E4EU,
    0x38383838U, 0x8A8A8A8AU, 0x72727272U, 0x14141414U,
    0xE7E7E7E7U, 0xC6C6C6C6U, 0xDEDEDEDEU, 0x50505050U,
    0x8E8E8E8EU, 0x92929292U, 0xD1D1D1D1U, 0x77777777U,
    0x93939393U, 0x45454545U, 0x9A9A9A9AU, 0xCECECECEU,
    0x2D2D2D2DU, 0x03030303U, 0x62626262U, 0xB6B6B6B6U,
    0xB9B9B9B9U, 0xBFBFBFBFU, 0x96969696U, 0x6B6B6B6BU,
    0x3F3F3F3FU, 0x07070707U, 0x12121212U, 0xAEAEAEAEU,
    0x40404040U, 0x34343434U, 0x46464646U, 0x3E3E3E3EU,
    0xDBDBDBDBU, 0xCFCFCFCFU, 0xECECECECU, 0xCCCCCCCCU,
    0xC1C1C1C1U, 0xA1A1A1A1U, 0xC0C0C0C0U, 0xD6D6D6D6U,
    0x1D1D1D1DU, 0xF4F4F4F4U, 0x61616161U, 0x3B3B3B3BU,
    0x10101010U, 0xD8D8D8D8U, 0x68686868U, 0xA0A0A0A0U,
    0xB1B1B1B1U, 0x0A0A0A0AU, 0x69696969U, 0x6C6C6C6CU,
    0x49494949U, 0xFAFAFAFAU, 0x76767676U, 0xC4C4C4C4U,
    0x9E9E9E9EU, 0x9B9B9B9BU, 0x6E6E6E6EU, 0x99999999U,
    0xC2C2C2C2U, 0xB7B7B7B7U, 0x98989898U, 0xBCBCBCBCU,
    0x8F8F8F8FU, 0x85858585U, 0x1F1F1F1FU, 0xB4B4B4B4U,
    0xF8F8F8F8U, 0x11111111U, 0x2E2E2E2EU, 0x00000000U,
    0x25252525U, 0x1C1C1C1CU, 0x2A2A2A2AU, 0x3D3D3D3DU,
    0x05050505U, 0x4F4F4F4FU, 0x7B7B7B7BU, 0xB2B2B2B2U,
    0x32323232U, 0x90909090U, 0xAFAFAFAFU, 0x19191919U,
    0xA3A3A3A3U, 0xF7F7F7F7U, 0x73737373U, 0x9D9D9D9DU,
    0x15151515U, 0x74747474U, 0xEEEEEEEEU, 0xCACACACAU,
    0x9F9F9F9FU, 0x0F0F0F0FU, 0x1B1B1B1BU, 0x75757575U,
    0x86868686U, 0x84848484U, 0x9C9C9C9CU, 0x4A4A4A4AU,
    0x97979797U, 0x1A1A1A1AU, 0x65656565U, 0xF6F6F6F6U,
    0xEDEDEDEDU, 0x09090909U, 0xBBBBBBBBU, 0x26262626U,
    0x83838383U, 0xEBEBEBEBU, 0x6F6F6F6FU, 0x81818181U,
    0x04040404U, 0x6A6A6A6AU, 0x43434343U, 0x01010101U,
    0x17171717U, 0xE1E1E1E1U, 0x87878787U, 0xF5F5F5F5U,
    0x8D8D8D8DU, 0xE3E3E3E3U, 0x23232323U, 0x80808080U,
    0x44444444U, 0x16161616U, 0x66666666U, 0x21212121U,
    0xFEFEFEFEU, 0xD5D5D5D5U, 0x31313131U, 0xD9D9D9D9U,
    0x35353535U, 0x18181818U, 0x02020202U, 0x64646464U,
    0xF2F2F2F2U, 0xF1F1F1F1U, 0x56565656U, 0xCDCDCDCDU,
    0x82828282U, 0xC8C8C8C8U, 0xBABABABAU, 0xF0F0F0F0U,
    0xEFEFEFEFU, 0xE9E9E9E9U, 0xE8E8E8E8U, 0xFDFDFDFDU,
    0x89898989U, 0xD7D7D7D7U, 0xC7C7C7C7U, 0xB5B5B5B5U,
    0xA4A4A4A4U, 0x2F2F2F2FU, 0x95959595U, 0x13131313U,
    0x0B0B0B0BU, 0xF3F3F3F3U, 0xE0E0E0E0U, 0x37373737U,
};

static const uint32_t T5[256] = {
    0x00000000U, 0x01020608U, 0x02040C10U, 0x03060A18U,
    0x04081820U, 0x050A1E28U, 0x060C1430U, 0x070E1238U,
    0x08103040U, 0x09123648U, 0x0A143C50U, 0x0B163A58U,
    0x0C182860U, 0x0D1A2E68U, 0x0E1C2470U, 0x0F1E2278U,
    0x10206080U, 0x11226688U, 0x12246C90U, 0x13266A98U,
    0x142878A0U, 0x152A7EA8U, 0x162C74B0U, 0x172E72B8U,
    0x183050C0U, 0x193256C8U, 0x1A345CD0U, 0x1B365AD8U,
    0x1C3848E0U, 0x1D3A4EE8U, 0x1E3C44F0U, 0x1F3E42F8U,
    0x2040C01DU, 0x2142C615U, 0x2244CC0DU, 0x2346CA05U,
    0x2448D83DU, 0x254ADE35U, 0x264CD42DU, 0x274ED225U,
    0x2850F05DU, 0x2952F655U, 0x2A54FC4DU, 0x2B56FA45U,
    0x2C58E87DU, 0x2D5AEE75U, 0x2E5CE46DU, 0x2F5EE265U,
    0x3060A09DU, 0x3162A695U, 0x3264AC8DU, 0x3366AA85U,
    0x3468B8BDU, 0x356ABEB5U, 0x366CB4ADU, 0x376EB2A5U,
    0x387090DDU, 0x397296D5U, 0x3A749CCDU, 0x3B769AC5U,
    0x3C7888FDU, 0x3D7A8EF5U, 0x3E7C84EDU, 0x3F7E82E5U,
    0x40809D3AU, 0x41829B32U, 0x4284912AU, 0x43869722U,
    0x4488851AU, 0x458A8312U, 0x468C890AU, 0x478E8F02U,
    0x4890AD7AU, 0x4992AB72U, 0x4A94A16AU, 0x4B96A762U,
    0x4C98B55AU, 0x4D9AB352U, 0x4E9CB94AU, 0x4F9EBF42U,
    0x50A0FDBAU, 0x51A2FBB2U, 0x52A4F1AAU, 0x53A6F7A2U,
    0x54A8E59AU, 0x55AAE392U, 0x56ACE98AU, 0x57AEEF82U,
    0x58B0CDFAU, 0x59B2CBF2U, 0x5AB4C1EAU, 0x5BB6C7E2U,
    0x5CB8D5DAU, 0x5DBAD3D2U, 0x5EBCD9CAU, 0x5FBEDFC2U,
    0x60C05D27U, 0x61C25B2FU, 0x62C45137U, 0x63C6573FU,
    0x64C84507U, 0x65CA430FU, 0x66CC4917U, 0x67CE4F1FU,
    0x68D06D67U, 0x69D26B6FU, 0x6AD46177U, 0x6BD6677FU,
    0x6CD87547U, 0x6DDA734FU, 0x6EDC7957U, 0x6FDE7F5FU,
    0x70E03DA7U, 0x71E23BAFU, 0x72E431B7U, 0x73E637BFU,
    0x74E82587U, 0x75EA238FU, 0x76EC2997U, 0x77EE2F9FU,
    0x78F00DE7U, 0x79F20BEFU, 0x7AF401F7U, 0x7BF607FFU,
    0x7CF815C7U, 0x7DFA13CFU, 0x7EFC19D7U, 0x7FFE1FDFU,
    0x801D2774U, 0x811F217CU, 0x82192B64U, 0x831B2D6CU,
    0x84153F54U, 0x8517395CU, 0x86113344U, 0x8713354CU,
    0x880D1734U, 0x890F113CU, 0x8A091B24U, 0x8B0B1D2CU,
    0x8C050F14U, 0x8D07091CU, 0x8E010304U, 0x8F03050CU,
    0x903D47F4U, 0x913F41FCU, 0x92394BE4U, 0x933B4DECU,
    0x94355FD4U, 0x953759DCU, 0x963153C4U, 0x973355CCU,
    0x982D77B4U, 0x992F71BCU, 0x9A297BA4U, 0x9B2B7DACU,
    0x9C256F94U, 0x9D27699CU, 0x9E216384U, 0x9F23658CU,
    0xA05DE769U, 0xA15FE161U, 0xA259EB79U, 0xA35BED71U,
    0xA455FF49U, 0xA557F941U, 0xA651F359U, 0xA753F551U,
    0xA84DD729U, 0xA94FD121U, 0xAA49DB39U, 0xAB4BDD31U,
    0xAC45CF09U, 0xAD47C901U, 0xAE41C319U, 0xAF43C511U,
    0xB07D87E9U, 0xB17F81E1U, 0xB2798BF9U, 0xB37B8DF1U,
    0xB4759FC9U, 0xB57799C1U, 0xB67193D9U, 0xB77395D1U,
    0xB86DB7A9U, 0xB96FB1A1U, 0xBA69BBB9U, 0xBB6BBDB1U,
    0xBC65AF89U, 0xBD67A981U, 0xBE61A399U, 0xBF63A591U,
    0xC09DBA4EU, 0xC19FBC46U, 0xC299B65EU, 0xC39BB056U,
    0xC495A26EU, 0xC597A466U, 0xC691AE7EU, 0xC793A876U,
    0xC88D8A0EU, 0xC98F8C06U, 0xCA89861EU, 0xCB8B8016U,
    0xCC85922EU, 0xCD879426U, 0xCE819E3EU, 0xCF839836U,
    0xD0BDDACEU, 0xD1BFDCC6U, 0xD2B9D6DEU, 0xD3BBD0D6U,
    0xD4B5C2EEU, 0xD5B7C4E6U, 0xD6B1CEFEU, 0xD7B3C8F6U,
    0xD8ADEA8EU, 0xD9AFEC86U, 0xDAA9E69EU, 0xDBABE096U,
    0xDCA5F2AEU, 0xDDA7F4A6U, 0xDEA1FEBEU, 0xDFA3F8B6U,
    0xE0DD7A53U, 0xE1DF7C5BU, 0xE2D97643U, 0xE3DB704BU,
    0xE4D56273U, 0xE5D7647BU, 0xE6D16E63U, 0xE7D3686BU,
    0xE8CD4A13U, 0xE9CF4C1BU, 0xEAC94603U, 0xEBCB400BU,
    0xECC55233U, 0xEDC7543BU, 0xEEC15E23U, 0xEFC3582BU,
    0xF0FD1AD3U, 0xF1FF1CDBU, 0xF2F916C3U, 0xF3FB10CBU,
    0xF4F502F3U, 0xF5F704FBU, 0xF6F10EE3U, 0xF7F308EBU,
    0xF8ED2A93U, 0xF9EF2C9BU, 0xFAE92683U, 0xFBEB208BU,
    0xFCE532B3U, 0xFDE734BBU, 0xFEE13EA3U, 0xFFE338ABU,
};

/** Round Constants **/
static const uint32_t rc[] = {
    0xA7D3E671U, 0xD0AC4D79U, 0x3AC991FCU, 0x1E4754BDU,
    0x8CA57AFBU, 0x63B8DDD4U, 0xE5B3C5BEU, 0xA9880CA2U,
    0x39DF29DAU, 0x2BA8CB4CU, 0x4B22AA24U, 0x4170A6F9U,
    0x5AE2B036U, 0x7DE433FFU, 0x6020088BU, 0x5EAB7F78U,
    0x7C2C57D2U, 0xDC6D7E0DU, 0x5394C328U,
};

/* context and configuration */
typedef struct 
{
    uint32_t bits;          // inisialisasi sebelum key_setup
    uint32_t R;
    uint32_t rkeys_enc[MAX_ROUNDS + 1][4];
    uint32_t rkeys_dec[MAX_ROUNDS + 1][4];
} anubis_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(anubis_t * config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(anubis_t * config, uint8_t val[BLOCKSIZEB]);
void key_setup(anubis_t * config, uint8_t * secret, uint32_t bits);

void block_crypt(uint8_t val[BLOCKSIZEB], const uint32_t rkeys[MAX_ROUNDS + 1][4], int R);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */
/** Electronic Code Book mode **/
void encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);
void decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);

/** Cipher Block Chaining mode **/
void encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Cipher Feedback mode **/
void encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Counter mode **/
void encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);
void decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);

/** Output Feedback mode **/
void encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Propagating Cipher Block Chaining mode **/
void encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan Anubis. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_encrypt(anubis_t * config, uint8_t val[BLOCKSIZEB])
{
    block_crypt(val, config->rkeys_enc, config->R);
}

/* 
    Dekripsi sebuah block dengan Anubis. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_decrypt(anubis_t * config, uint8_t val[BLOCKSIZEB])
{
    block_crypt(val, config->rkeys_dec, config->R);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
/* Fungsi utama untuk melakukan enkripsi / dekripsi block data. */
void 
block_crypt(uint8_t val[BLOCKSIZEB], const uint32_t rkeys[MAX_ROUNDS + 1][4], int R)
{
    int i, pos, r;
    uint32_t state[4];
    uint32_t inter[4];

    /* petakan plaintext ke ciphertext dan tambahkan initial round key (sigma[K^0]) */
    for (i = 0, pos = 0; i < 4; i++, pos += 4)
    {
        state[i] = 
            (val[pos    ] << 24) ^  
            (val[pos + 1] << 16) ^  
            (val[pos + 2] <<  8) ^  
            (val[pos + 3]      ) ^ 
            rkeys[0][i];
    }

    /* R - 1 full rounds */
    for (r = 1; r < R; r++) 
    {
        /* Gunakan S-Box untuk mengubah state */
		inter[0] =
			T0[(state[0] >> 24)       ] ^
			T1[(state[1] >> 24)       ] ^
			T2[(state[2] >> 24)       ] ^
			T3[(state[3] >> 24)       ] ^
			rkeys[r][0];
		inter[1] =
			T0[(state[0] >> 16) & 0xFF] ^
			T1[(state[1] >> 16) & 0xFF] ^
			T2[(state[2] >> 16) & 0xFF] ^
			T3[(state[3] >> 16) & 0xFF] ^
			rkeys[r][1];
		inter[2] =
			T0[(state[0] >>  8) & 0xFF] ^
			T1[(state[1] >>  8) & 0xFF] ^
			T2[(state[2] >>  8) & 0xFF] ^
			T3[(state[3] >>  8) & 0xFF] ^
			rkeys[r][2];
		inter[3] =
			T0[(state[0]      ) & 0xFF] ^
			T1[(state[1]      ) & 0xFF] ^
			T2[(state[2]      ) & 0xFF] ^
			T3[(state[3]      ) & 0xFF] ^
			rkeys[r][3];

		state[0] = inter[0];
		state[1] = inter[1];
		state[2] = inter[2];
		state[3] = inter[3];
    }

    /* last round */
	inter[0] =
		(T0[(state[0] >> 24)       ] & 0xff000000U) ^
		(T1[(state[1] >> 24)       ] & 0x00ff0000U) ^
		(T2[(state[2] >> 24)       ] & 0x0000ff00U) ^
		(T3[(state[3] >> 24)       ] & 0x000000ffU) ^
		rkeys[R][0];
	inter[1] =
		(T0[(state[0] >> 16) & 0xff] & 0xff000000U) ^
		(T1[(state[1] >> 16) & 0xff] & 0x00ff0000U) ^
		(T2[(state[2] >> 16) & 0xff] & 0x0000ff00U) ^
		(T3[(state[3] >> 16) & 0xff] & 0x000000ffU) ^
		rkeys[R][1];
	inter[2] =
		(T0[(state[0] >>  8) & 0xff] & 0xff000000U) ^
		(T1[(state[1] >>  8) & 0xff] & 0x00ff0000U) ^
		(T2[(state[2] >>  8) & 0xff] & 0x0000ff00U) ^
		(T3[(state[3] >>  8) & 0xff] & 0x000000ffU) ^
		rkeys[R][2];
	inter[3] =
		(T0[(state[0]      ) & 0xff] & 0xff000000U) ^
		(T1[(state[1]      ) & 0xff] & 0x00ff0000U) ^
		(T2[(state[2]      ) & 0xff] & 0x0000ff00U) ^
		(T3[(state[3]      ) & 0xff] & 0x000000ffU) ^
		rkeys[R][3];

    /* petakan data block yang telah ditransformasi */
    for (i = 0, pos = 0; i < 4; i++, pos += 4)
    {
        uint32_t w = inter[i];
        val[pos    ] = (uint8_t) (w >> 24);
        val[pos + 1] = (uint8_t) (w >> 16);
        val[pos + 2] = (uint8_t) (w >>  8);
        val[pos + 3] = (uint8_t) (w      );
    }
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void 
key_setup(anubis_t * config, uint8_t * secret, uint32_t bits)
{
    int N, R, i, pos, r;
    uint32_t kappa[MAX_N];
    uint32_t inter[MAX_N];

    config->bits = bits;

    /* tentukan parameter N */
    N = config->bits >> 5;

    /* tentukan jumlah round dari key size */
    config->R = R = 8 + N;

    /* petakan cipher key ke initial key state (mu) */
    for (i = 0, pos = 0; i < N; i++, pos += 4)
    {
        kappa[i] = 
            (secret[pos    ] << 24) ^ (secret[pos + 1] << 16) ^
            (secret[pos + 2] <<  8) ^ (secret[pos + 3]);
    }

    /* bangkitkan R + 1 round keys */
    for  (r = 0; r <= R; r++)
    {
        uint32_t K0, K1, K2, K3;

        /* bangkitkan round key ke-r K^r: */
        K0 = T4[(kappa[N - 1] >> 24)       ];
        K1 = T4[(kappa[N - 1] >> 16) & 0xFF];
        K2 = T4[(kappa[N - 1] >>  8) & 0xFF];
        K3 = T4[(kappa[N - 1]      ) & 0xFF];

        for (i = N - 2; i >= 0; i--)
        {
			K0 = T4[(kappa[i] >> 24)       ] ^
				(T5[(K0 >> 24)       ] & 0xFF000000U) ^
				(T5[(K0 >> 16) & 0xFF] & 0x00FF0000U) ^
				(T5[(K0 >>  8) & 0xFF] & 0x0000FF00U) ^
				(T5[(K0      ) & 0xFF] & 0x000000FFU);
			K1 = T4[(kappa[i] >> 16) & 0xFF] ^
				(T5[(K1 >> 24)       ] & 0xFF000000U) ^
				(T5[(K1 >> 16) & 0xFF] & 0x00FF0000U) ^
				(T5[(K1 >>  8) & 0xFF] & 0x0000FF00U) ^
				(T5[(K1      ) & 0xFF] & 0x000000FFU);
			K2 = T4[(kappa[i] >>  8) & 0xFF] ^
				(T5[(K2 >> 24)       ] & 0xFF000000U) ^
				(T5[(K2 >> 16) & 0xFF] & 0x00FF0000U) ^
				(T5[(K2 >>  8) & 0xFF] & 0x0000FF00U) ^
				(T5[(K2      ) & 0xFF] & 0x000000FFU);
			K3 = T4[(kappa[i]      ) & 0xFF] ^
				(T5[(K3 >> 24)       ] & 0xFF000000U) ^
				(T5[(K3 >> 16) & 0xFF] & 0x00FF0000U) ^
				(T5[(K3 >>  8) & 0xFF] & 0x0000FF00U) ^
				(T5[(K3      ) & 0xFF] & 0x000000FFU);
        }

        config->rkeys_enc[r][0] = K0;
        config->rkeys_enc[r][1] = K1;
        config->rkeys_enc[r][2] = K2;
        config->rkeys_enc[r][3] = K3;

        /* hitung kappa ^ {r+1} dari kappa^r: */
        if (r == R)
            break;
        
        for (i = 0; i < N; i++)
        {
            int j = i;
            inter[i]  = T0[(kappa[j--] >> 24)       ]; if (j < 0) j = N - 1;
            inter[i] ^= T1[(kappa[j--] >> 16) & 0xFF]; if (j < 0) j = N - 1;
            inter[i] ^= T2[(kappa[j--] >>  8) & 0xFF]; if (j < 0) j = N - 1;
            inter[i] ^= T3[(kappa[j  ]      ) & 0xFF];
        }

        kappa[0] = inter[0] ^ rc[r];
        for (i = 1; i < N; i++)
            kappa[i] = inter[i];
    }

    /* bangkitkan inverse key: K'^0 = K^R, K'^R = K^0, K'^r = theta(K^{R-r}) */
    for (i = 0; i < 4; i++)
    {
        config->rkeys_dec[0][i] = config->rkeys_enc[R][i];
        config->rkeys_dec[R][i] = config->rkeys_enc[0][i];
    }
    for (r = 1; r < R; r++) 
    {
        for (i = 0; i < 4; i++)
        {
            uint32_t v = config->rkeys_enc[R - r][i];
            config->rkeys_dec[r][i] = 
                T0[T4[(v >> 24)       ] & 0xFF] ^
                T1[T4[(v >> 16) & 0xFF] & 0xFF] ^
                T2[T4[(v >>  8) & 0xFF] & 0xFF] ^
                T3[T4[(v      ) & 0xFF] & 0xFF];
        }
    }
}


/* *************************** HELPER FUNCTIONS *************************** */
/* Xor 2 block data */
void 
xor_block(uint8_t* dst, const uint8_t * src1, const uint8_t * src2)
{
    register uint32_t i = 0;
    for (i = 0; i < BLOCKSIZEB; i++)
        dst[i] = src1[i] ^ src2[i];
}


/* ******************* MODE OF OPERATIONS IMPLEMENTATION ******************* */
/*
    Enkripsi block data dengan mode ECB.
    Enkripsi diberlakukan secara independen tanpa ada hubungan dengan block
    sebelum dan berikutnya.
    Pastikan jumlah block valid.
*/
void 
encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t   i;
    anubis_t   config;

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    for (i = 0; i < length; i += BLOCKSIZEB)
        block_encrypt(&config, &data[i]);
}

/*
    Dekripsi block data dengan mode ECB.
    Dekripsi diberlakukan secara independen tanpa ada hubungan dengan block
    sebelum dan berikutnya.
    Pastikan jumlah block valid.
*/
void 
decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t   i;
    anubis_t   config;

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    for(i = 0; i < length; i += BLOCKSIZEB)
        block_decrypt(&config, &data[i]);
}


/*
    Enkripsi block data dengan mode CBC.
    Sebelum enkripsi, plaintext akan di-XOR dengan block sebelumnya.
    Pastikan jumlah block valid.
*/
void 
encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t  * prev_block = iv;

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // XOR block plaintext dengan block ciphertext sebelumnya
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi plaintext menjadi ciphertext
        block_encrypt(&config, &data[i]);

        // Simpan block ciphertext untuk operasi XOR selanjutnya
        prev_block = &data[i];
    }
}

/*
    Dekripsi block data dengan mode CBC.
    Setelah dekripsi, plaintext akan di-XOR dengan block sebelumnya.
    Pastikan jumlah block valid.
*/
void 
decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block ciphertext untuk operasi XOR berikutnya.
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext menjadi block
        block_decrypt(&config, &data[i]);

        // XOR block block dengan block ciphertext sebelumnya
        // gunakan IV bila ini adalah block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Pindahkan block ciphertext yang telah disimpan
        memcpy(prev_block, ctext_block, BLOCKSIZEB);
    }
}


/*
    Enkripsi block data dengan mode CFB.
    Pastikan jumlah block valid.
*/
void 
encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t    prev_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        block_encrypt(&config, prev_block);

        // XOR dengan plaintext untuk mendapatkan ciphertext
        xor_block(&data[i], &data[i], prev_block);

        // Simpan block ciphertext untuk operasi XOR berikutnya
        memcpy(prev_block, &data[i], BLOCKSIZEB);
    }
}

/*
    Dekripsi block data dengan mode CFB.
    Pastikan jumlah block valid.
*/
void 
decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block cipher untuk operasi
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        block_encrypt(&config, prev_block);

        // XOR dengan plaintext untuk mendapatkan ciphertext
        xor_block(&data[i], &data[i], prev_block);

        // Simpan block ciphertext untuk operasi XOR berikutnya
        memcpy(prev_block, ctext_block, BLOCKSIZEB);
    }
}

/*
    Enkripsi block data dengan mode CTR.
    Pastikan jumlah block valid.
*/
void 
encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t    local_nonce[BLOCKSIZEB];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[BLOCKSIZEB-4];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(local_nonce, nonce, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi nonce + counter
        block_encrypt(&config, local_nonce);

        // XOR nonce terenkripsi dengan plaintext untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], local_nonce);

        // Naikkan nilai nonce dengan 1.
        (*nonce_counter) ++;
    }
}

/*
    Enkripsi block data dengan mode CTR.
    Pastikan jumlah block valid.
*/
void 
decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t    local_nonce[BLOCKSIZEB];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[BLOCKSIZEB-4];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(local_nonce, nonce, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi nonce + counter
        block_encrypt(&config, local_nonce);

        // XOR nonce terenkripsi dengan plaintext untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], local_nonce);

        // Naikkan nilai nonce dengan 1.
        (*nonce_counter) ++;
    }
}


/*
    Enkripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t    prev_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);
    
    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi block sebelumnya 
        // gunakan IV bila ini block pertama
        block_encrypt(&config, prev_block);

        // XOR plaintext dengan output dari enkripsi untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], prev_block);
    }
}

/*
    Dekripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t    prev_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);
    
    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi block sebelumnya 
        // gunakan IV bila ini block pertama
        block_encrypt(&config, prev_block);

        // XOR plaintext dengan output dari enkripsi untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], prev_block);
    }
}


/*
    Enkripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ptext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan plaintext untuk dioperasikan dengan block berikutnya.
        memcpy(ptext_block, &data[i], BLOCKSIZEB);

        // XOR plaintext dengan block sebelumnya
        // gunakan IV bila ini block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi
        block_encrypt(&config, &data[i]);

        // Hitung block berikutnya
        xor_block(prev_block, ptext_block, &data[i]);
    }
}

/*
    Dekripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    anubis_t   config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan ciphertext untuk dioperasikan dengan block berikutnya.
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext untuk mendapatkan plaintext ter-XOR
        block_decrypt(&config, &data[i]);

        // XOR dengan block sebelumnya
        // gunakan IV bila ini block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Hitung block berikutnya
        xor_block(prev_block, ctext_block, &data[i]);
    }
}
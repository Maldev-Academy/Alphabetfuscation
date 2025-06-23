## Alphabetfuscation: Convert your shellcode into an ASCII string

</br>

### Quick Links

[Maldev Academy Home](https://maldevacademy.com)
  
[Maldev Academy Syllabus](https://maldevacademy.com/syllabus)

[Offensive Phishing Operations](https://maldevacademy.com/phishing-course)

</br>

## Available Versions

1. **[main](https://github.com/Maldev-Academy/Alphabetfuscation)** – The default implementation. Converts shellcode into randomized alphabetical letters (A–Z, a–z).
2. **[entropy-favored](https://github.com/Maldev-Academy/Alphabetfuscation/tree/entropy-favored)** – A variation that *reduces entropy* by:
   - Limiting output to **uppercase letters only** (A–Z)
   - Introducing **random spaces** between letters to simulate natural text appearance

The version documented in this *README* refers to the `main` branch.

</br>


## How It Works

**1. Encoding:**

* For each raw byte, we determine a random alphabetical offset (A–Z or a–z) via `RDRAND`.
* Add offset to the byte, rotate the result by 4 bits, then XOR with `0xA5` (which is user-adjustable). 
* If the resulting byte is not within the ASCII alpha ranges (A–Z or a–z), another offset is chosen.

</br>

**2. Optional Shuffle Mode:**

If `SHUFFLE_ORDER` is defined, the input shellcode is preprocessed by grouping into 32-bit `DWORD`s and applying a 16-bit half-word swap. This obfuscates control flow patterns and hinders static signatures before the encoding step.

</br>

**3. Decoding:**

* Split each output word into offset (high byte) and transformed (low byte).
* Reverse operations: undo XOR, rotate right by 4, then subtract the offset to recover the original byte.
* If Shuffle mode was used during encoding, inverse reordering is applied at the end to fully restore the payload.

</br>


## Output Example

Even with the same input shellcode and XOR key, the output changes across runs due to per-byte randomization:

![image](https://github.com/user-attachments/assets/46afcaff-3a53-45aa-afb5-ed0ad03d3065)


</br>



### Encoding Function

```C
BOOL AlphabaticalShellcodeEncode(
    IN  PBYTE  pRawHexShellcode,
    IN  DWORD  dwRawHexShellcodeSize,
    OUT PBYTE* ppEncodedShellcode,
    OUT PDWORD pdwEncodedShellcodeSize
);
```

* `pRawHexShellcode` - Base address of the plaintext shellcode to be encoded.
* `dwRawHexShellcodeSize` - The size, in bytes, of the plaintext shellcode.
* `ppEncodedShellcode` - Output parameter, representing a pointer to a `PBYTE` variable that will receive the address of the encoded shellcode (ASCII string).
* `pdwEncodedShellcodeSize` - Output parameter, representing a pointer to a `DWORD` variable that will receive the size of the encoded shellcode in bytes.


</br>

### Decoding Function


```C
BOOL AlphabaticalShellcodeDecode(
    IN  PBYTE  pEncodedShellcode,
    IN  DWORD  dwEncodedShellcodeSize,
    OUT PBYTE* ppDecodedShellcode,
    OUT PDWORD pdwDecodedShellcodeSize
);
```

* `pEncodedShellcode` - Base address of the encoded ASCII shellcode to be decoded.
* `dwEncodedShellcodeSize` - The size, in bytes, of the encoded buffer.
* `ppDecodedShellcode` - Output parameter, representing a pointer to a `PBYTE` variable that will receive the address of the decoded shellcode.
* `pdwDecodedShellcodeSize` - Output parameter, representing a pointer to a `DWORD` variable that will receive the size of the decoded shellcode in bytes.



</br>


## Downside

The encoded output is **2 times larger** than the input (since each byte is transformed into a 2-byte `WORD`).










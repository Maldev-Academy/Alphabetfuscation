## Alphabetfuscation v2: Convert your shellcode into an ASCII string favoring entropy reduction

</br>

### Quick Links

[Maldev Academy Home](https://maldevacademy.com)
  
[Maldev Academy Syllabus](https://maldevacademy.com/syllabus)

[Offensive Phishing Operations](https://maldevacademy.com/phishing-course)

</br>


## How It Works

**1. Encoding:**

* For each raw byte, we determine a random capitalized alphabetical offset (A–Z) via `RDRAND`.
* Add offset to the byte, rotate the result by 4 bits, then XOR with `0xA5` (which is user-adjustable). 
* If the resulting byte is not within the ASCII alpha ranges (A–Z), another offset is chosen.


</br>

**2. Optional Shuffle Mode:**

If `SHUFFLE_ORDER` is defined, the input shellcode is preprocessed by grouping into 32-bit `DWORD`s and applying a 16-bit half-word swap. This obfuscates control flow patterns and hinders static signatures before the encoding step.

</br>


**3. Space Injection Mode:**

If `INJECT_SPACES` is defined, we iterate through the encoded shellcode and inject space characters between some alphabetical letters to reduce output uniformity and evade pattern-based detection. This mode uses:

- `MIN_SPACE_INJECT` – Minimum number of letters to emit before a space **might** be inserted.
- `MAX_SPACE_INJECT` – Maximum number of letters to emit before a new injection decision is made.

Once the randomized interval threshold is met, there is a **75% chance** of inserting a space (i.e., only 1 in 4 intervals skip the space). This random spacing helps obfuscate the encoded string and mimic natural-language structure to further evade static detection heuristics.

</br>

**4. Decoding:**

* Split each output word into offset (high byte) and transformed (low byte).
* If space injection mode was used during encoding, `StripSpaces` is called to strip all space characters from the encoded shellcode before any decoding.
* Reverse operations: undo XOR, rotate right by 4, then subtract the offset to recover the original byte.
* If Shuffle mode was used during encoding, inverse reordering is applied at the end to fully restore the payload.

</br>


## Output Example

The following output is the result of the `INJECT_SPACES` mode being defined (output is truncated due to its size):

![image](https://github.com/user-attachments/assets/66d6e85c-bcdb-4971-87b7-f13c3ebd3d7e)


This lowers the entropy from `5.92` to `4.21`, as shown in the image below:

![image](https://github.com/user-attachments/assets/3fa13d2e-d84e-415a-9994-0c173478fd4f)


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

The encoded output is at least **2 times larger** than the input (since each byte is transformed into a 2-byte `WORD`). If `INJECT_SPACES` is enabled, the size increases further due to randomly inserted space characters, resulting in an output that is **more than double** the original size.







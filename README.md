# MD5 Encoder and Decoder

This software tool lets you convert lists of words into MD5 hashes (encoding) and potentially retrieve the original words from those hashes (decoding).

## Understanding MD5

- **MD5 (Message-Digest Algorithm 5)** is a cryptographic hash function that takes an input of any length and generates a fixed-size (128-bit) output called a hash.
- This hash is a unique "fingerprint" of the original data.
- Any change to the data will result in a different hash.

## What are Collisions?

- In theory, different inputs should always produce different MD5 hashes. However, there's a small chance of collisions, where two different inputs generate the same hash.
- While unlikely for short inputs, collisions become more probable with larger data sets.
- This is why decoding with MD5 is not guaranteed to recover the original data perfectly. It might return multiple possibilities for a single hash.

## Data Integrity with MD5 ✅

- MD5 is often used to verify data integrity. You can calculate the MD5 hash of a file before downloading or transferring it.
- After receiving the file, you can calculate its MD5 hash again.
- If the two hashes match, it's highly likely that the data hasn't been tampered with during transmission.

## Important Notes

- Due to potential collisions, MD5 is not recommended for applications requiring strong security (e.g., storing passwords). Consider using more robust hashing algorithms like SHA-256.
- The provided tool (MD5_HELPER.cpp) may have bugs when running the executable directly. Using an IDE like VS Code is recommended for a smoother experience.

## Usage Instructions

1. **Compile and Run MD5_HELPER.cpp**
    - Follow your preferred C++ compiler's instructions for compilation.

2. **Encoding**
    - Press `E` to enter encoding mode.
    - Provide the exact path (not relative path) to the file containing the list of words to encode.
    - Provide the exact path to the output file where you want to store the generated MD5 hashes.

3. **Decoding**
    - Press `D` to enter decoding mode.
    - Enter the MD5 hash you want to decode.
    - Provide the exact path to a text file containing a potential set of strings for comparison.
    - The output, including any potential collisions (multiple strings for the same hash), will be displayed in the terminal.

## Additional Considerations

- Decoding success depends heavily on the quality of the provided potential string set.
- This tool is for educational purposes and should not be used for sensitive data due to MD5's limitations.

## Reference

- For more detailed information about MD5, you can refer to [RFC 1321](https://dl.acm.org/doi/10.17487/RFC1321).

## About Ronald Rivest

- MD5 was designed by Ronald Rivest in 1991. Rivest is a renowned cryptographer and one of the co-founders of RSA encryption, which is widely used for securing data transmission. His research and contributions to cryptography have had a profound impact on data security and encryption standards.

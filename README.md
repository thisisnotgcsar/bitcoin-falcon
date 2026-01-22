# Falcon Signature Scheme Integration in Bitcoin Core

## Overview

This code demonstrates the integration (as a soft-fork) and benchmarking of the Falcon post-quantum signature scheme (Falcon-512) in Bitcoin Core. Comparison results are provided with respect to the traditional ECDSA scheme within Bitcoin's script verification framework.

This project serves as a practical demonstration of Falcon’s promising performance, highlighting its advantages over currently selected post-quantum signature algorithms such as SPHINCS+ and ML-DSA, which face significant time and space limitations. As Falcon approaches FIPS standardization, this work provides a valuable reference for future adoption and integration in Bitcoin and similar systems.

## Why Falcon?

Falcon is a lattice-based, post-quantum digital signature scheme designed to be secure against quantum attacks. It is a candidate for standardization in the upcoming FIPS standard ([NIST PQC Falcon](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022#falcon)). Unlike other post-quantum signature schemes, Falcon is characterized by relatively small signature and public key sizes, as well as efficient signature and verification times.  
Falcon is implemented in pure C and does not require any external dependencies.

### Falcon vs ECDSA: Time and Space Performance

| Aspect                | Falcon (logn=9) | ECDSA         |
|-----------------------|-----------------|--------------|
| Public Key Size (B)   | 897             | 33           |
| Signature Size (B)    | 655             | 71           |
| Verification Time (μs)| 57              | 120          |

> These results were obtained on an Intel(R) N150 CPU (4 cores), 16 GB DDR4 RAM, Ubuntu 24.04, using GCC 13.3.0.  
> Verification time is more important than signature creation time, as in Bitcoin, signature creation is performed by clients (wallets), not nodes. The network's main concern is verification speed.

## Integration

The scheme has been implemented within the classic P2WPKH mode as a soft-fork. A new script verification flag called `SCRIPT_VERIFY_FALCON` has been added in the [interpreter.h](src/script/interpreter.h) header file to enable Falcon signature verification.

- Falcon software was obtained from the original authors' [GitHub repository](https://github.com/algorand/falcon) and included as-is in the Bitcoin Core codebase (following Bitcoin Core conventions for external libraries). It was compiled with its default settings and recommended compilation options as suggested by the authors. Note that an official FIPS standard has not yet been released by NIST.
- The [src/CMakeLists.txt](src/CMakeLists.txt) file was modified to include Falcon in the Bitcoin Core build process.

## Test

The test (see [src/test/falcon_script_tests.cpp](src/test/falcon_script_tests.cpp)) benchmarks and compares the Falcon-512 and ECDSA signature schemes within Bitcoin's script verification framework. For each scheme, it:

- Generates a keypair.
- Signs a dummy transaction hash.
- Constructs a P2WPKH (Pay-to-Witness-Public-Key-Hash) script using the corresponding public key.
- Verifies the signature using Bitcoin's script interpreter.
- Measures and prints the public key size, signature size, and verification time.

## Notes

- This is a demonstration and benchmarking tool, not a production-ready implementation. It is intended for research and reference as the Bitcoin ecosystem explores post-quantum security options.
- For more information on Falcon and its standardization, see the [NIST PQC Falcon page](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022#falcon).

---
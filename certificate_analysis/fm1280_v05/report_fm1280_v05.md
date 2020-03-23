# FM1280 V05

## TOE Description

The evaluated product was FM1280 V05 Dual Interface Smart Card Chip with IC Dedicated Software, ecure smart card integrated circuit with dedicated software, developed by Shanghai Fudan Microelectronics Groups Co., Ltd.; TOE is intended for use in banking and finance market, electronic commerce or governmental applications.

TOE uses standard as well as OTP EEPROM, ROM; system and coprocessor, PAE, and CLA RAM. TOE supports the following communication interfaces: ISO/IEC 14443 Type A contactless interface, ISO/IEC 7816 contact interface, GPIO, SPI and High Speed SPI, I2C, and UART. TOE includes the following coprocessors: CRC-CCITT, TRNG, DES/TDES, AES, PAE for RSA, PAE for ECC, Chinese Domestic Algorithm, and HASH (sha1/sha256). As hardware protection, TOE claims: Watch Dog Timer, Clock and Reset managment, Security Controller and Enviromental Detector Circuits (light sensors, temperature sensors, clock frequency monitors, voltage and glitch sensors), and active shielding.

The TOE provides RNG, DES/TDES, AES, RSA, ECC and SHA1/SHA256 by HASH as secure cryptographic services. DES and SHA only claim corectness, not security due to algorithms attack resistance. TOE claims the RNG provides high entropy true random numbers. TOEs driver provides CRC, EEPROM, and IO opperations. TOEs driver services have not been made resistant against attacks. 

## Assumed Attackers Model

In accordance to teh section 3.2 of the Secuirty IC Platform protection profile, there are following threads to the TOE (all of which the TOE claims to fulfil):
* Inherent information leakage (T.Leak-Inherent).
* Physical probing (T.Phys-Probing).
* Malfunction due to enviromental stress (T.Malfunction).
* Pysical manipulation (T.Phys-Manipulation).
* Forced information leakage (T.Leak-Forced).
* Abuse of functionality (T.Abuse-Func).
* Deficiency of random numbers (T.RND).  

An overview of mapping of s to Security Objectives for the TOE can be found in subsection 6.4.1 of the Security Target.

**Cryptographic Services** claimed to be fulfilled as security objectives add the:
* Security of RSA services for encryption and decryption (O.RSA).
* Security of ECC services for signature generation, signature verification, diffie-hellman key agreement, point multiplication and point addition (O.ECC).
* Security of the Triple-DES services for encryption and decryption (O.TDES).
* Security of the AES services for encryption and decryption (O.AES).

**Additional assumptions** are the TOEs comformance to:
* Protection during packaging, finishing and personalisation (A.Process-Sec-IC).
* Treament of user data (especially secret keys, A.Resp-Appl).

## Testing and Evaluation

**Delivery** was supposedly checked during the evaluation, and a recommendation is to check evaluated versions of the components are checked to have been supplied. 

**Vulnerability Analysis** was taken based on public domain sources and the visibility of TOE given by the evaluation. Idependent analysis was done based on: design and implementation review of TOE, code review of crypto library and boot code, validation tests of security features, review of previous results considering "JIL Attack Methods for Smartcards and Similiar Devices", penetration tests.

**Developer's tests** were supposedly performed on: engineering samples (cards or Dual-In_line_package ICs), wafers, simaltion tools to verify logical functions.

**Evaluator tests** were performed using the developers hardware testing tools and performing developers test cases. Chosen tests to be sampled were on: TSFI's, interfaces of SFR-enforcing modules, security mechanisms, all developer test methods (listed above). Addition tests were perfomed by augmenting existing tests by various parameters, and supplementation by applying developer tests to different samples then indended to (engineeering samples to wafer, etc.).

## Conclusion

The report and security target specifies the expected threat model in a great detail. Together with the evaluation, it gives a semblence of idea as to the tests performed, and a setup is given in the appendix of the report. Tests performed are, however, all closed only to developers, and hence possibly not easily reproduciable. This also hides any possible mistakes that could have been performed during testing. Errors in evaluation may have occured as well, as the testing results are not given (likely due to closed nature of tests).

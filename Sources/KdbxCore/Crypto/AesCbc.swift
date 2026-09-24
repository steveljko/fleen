import Foundation
import CommonCrypto

/// AES-256-CBC decryption with PKCS#7 padding, via CommonCrypto.
///
/// CryptoKit deliberately offers no CBC mode, and KDBX's default cipher
/// (`31C1F2E6-BF71-4350-BE58-05216AFC5AFF`) is AES-256-CBC, so CommonCrypto is the
/// right call here: Apple-maintained, and no block cipher written by hand.
enum AesCbc {
    private static func crypt(
        _ operation: Int,
        key: SecureBytes,
        iv: [UInt8],
        input: Data
    ) throws -> Data {
        guard key.count == kCCKeySizeAES256 else {
            throw KdbxError.cryptoFailure("AES-256 needs a 32-byte key")
        }
        guard iv.count == kCCBlockSizeAES128 else {
            throw KdbxError.cryptoFailure("AES-CBC needs a 16-byte IV")
        }

        var output = Data(count: input.count + kCCBlockSizeAES128)
        var written = 0

        let status: CCCryptorStatus = key.withUnsafeBytes { keyBuf in
            iv.withUnsafeBytes { ivBuf in
                input.withUnsafeBytes { inBuf in
                    output.withUnsafeMutableBytes { outBuf in
                        CCCrypt(
                            CCOperation(operation), CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBuf.baseAddress, kCCKeySizeAES256,
                            ivBuf.baseAddress,
                            inBuf.baseAddress, inBuf.count,
                            outBuf.baseAddress, outBuf.count,
                            &written)
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            // A padding failure here means the payload did not decrypt correctly.
            // Never surface which check failed to the user beyond "wrong key": the
            // distinction between a bad key and a corrupt file is itself a signal.
            throw KdbxError.cryptoFailure("AES-CBC operation failed (status \(status))")
        }
        return output.prefix(written)
    }

    static func decrypt(key: SecureBytes, iv: [UInt8], ciphertext: Data) throws -> Data {
        try crypt(kCCDecrypt, key: key, iv: iv, input: ciphertext)
    }
}

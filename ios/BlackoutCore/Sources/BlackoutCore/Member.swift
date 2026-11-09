import Foundation
import CryptoKit
import Security

/// Member keys and signatures (spec/FORMAT.md, "Member ids", "Signatures", "Person emoji"): P-256 with Apple's own
/// crypto. Same as Android's P256.kt.
public enum MemberKey {
    /// First 8 bytes of SHA-256(public key), as 16 lowercase hex chars.
    public static func id(_ pub: Data) -> String { Hex.encode(Data(SHA256.hash(data: pub)).prefix(8)) }

    /// The 16 emoji indices of a member's public key: the first 96 bits of the hash, 6 bits each.
    public static func emoji(_ pub: Data) -> [Int] {
        let h = Array(SHA256.hash(data: Data("darkproof-person-emoji-v1".utf8) + pub))
        return (0..<16).map { i in
            let bit = 6 * i, at = bit / 8
            return ((Int(h[at]) << 8 | Int(h[at + 1])) >> (10 - bit % 8)) & 63
        }
    }

    /// The key of a 33-byte compressed point, or nil if it isn't one on P-256.
    public static func publicKey(_ compressed: Data) -> P256.Signing.PublicKey? {
        guard compressed.count == 33, compressed.first == 2 || compressed.first == 3 else { return nil }
        return try? P256.Signing.PublicKey(compressedRepresentation: compressed)
    }

    /// Signs the whole signed message (spec "Signatures"); returns r ‖ s.
    public static func sign(_ key: P256.Signing.PrivateKey, _ msg: Data) throws -> Data { try key.signature(for: msg).rawRepresentation }

    /// A checker for one member's key: r ‖ s against SHA-256 of the signed message (`digest`).
    public final class Checker: @unchecked Sendable { // SecKey is thread-safe
        public let pub: Data
        private let key: SecKey?
        public init?(_ compressed: Data) {
            guard let k = MemberKey.publicKey(compressed) else { return nil }
            pub = compressed
            let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                        kSecAttrKeyClass as String: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits as String: 256]
            key = SecKeyCreateWithData(k.x963Representation as CFData, attrs as CFDictionary, nil)
            if key == nil { return nil }
        }
        public func verify(digest: Data, signature raw: Data) -> Bool {
            guard let key, raw.count == 64, let sig = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return SecKeyVerifySignature(key, .ecdsaSignatureDigestX962SHA256, digest as CFData, sig.derRepresentation as CFData, nil)
        }
    }
}

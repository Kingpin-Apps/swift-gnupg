import Foundation

/// Handles status messages during decryption operations
public final class DecryptResult: BaseStatusHandler, @unchecked Sendable {
    
    // MARK: - Properties
    
    public var status: String?
    public var keyId: String?
    public var username: String?
    public var fingerprint: String?
    public var timestamp: String?
    public var filename: String?
    public var plaintextLength: Int?
    public var isSymmetric: Bool = false
    public var publicKeyAlgorithm: String?
    public var symmetricAlgorithm: String?
    public var compressionAlgorithm: String?
    public var signatureInfo: [String: Any] = [:]
    
    // Logger removed for initial implementation
    
    public override init(gpg: GnuPG) {
        super.init(gpg: gpg)
    }
    
    /// Whether the decryption operation was successful
    public var isSuccessful: Bool {
        return status == "decryption ok"
    }
    
    public override func handleStatus(key: String, value: String) {
        if key == "WARNING" || key == "ERROR" || key == "FAILURE" {
            // Warning logging removed
            if status == nil {
                status = "\(key.lowercased()): \(value)"
            }
        } else if key == "BEGIN_DECRYPTION" {
            status = "decryption started"
        } else if key == "DECRYPTION_OK" {
            status = "decryption ok"
        } else if key == "DECRYPTION_FAILED" {
            status = "decryption failed"
        } else if key == "NO_SECKEY" {
            status = "no secret key"
            keyId = value
        } else if key == "BAD_PASSPHRASE" {
            status = "bad passphrase"
        } else if key == "GOOD_PASSPHRASE" {
            // Informational - passphrase is correct
            return
        } else if key == "NEED_PASSPHRASE" {
            // Format: NEED_PASSPHRASE <long_keyid> <main_keyid> <keytype> <keylength>
            let parts = value.split(separator: " ").map(String.init)
            if !parts.isEmpty {
                keyId = parts[0]
            }
        } else if key == "USERID_HINT" {
            // Format: USERID_HINT <long_keyid> <email_or_name>
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count >= 2 {
                keyId = parts[0]
                username = parts[1]
            }
        } else if key == "ENC_TO" {
            // Format: ENC_TO <long_keyid> <keytype> <keylength>
            // This tells us which key the message was encrypted to
            let parts = value.split(separator: " ").map(String.init)
            if !parts.isEmpty {
                keyId = parts[0]
            }
        } else if key == "DECRYPTION_INFO" {
            // Format: DECRYPTION_INFO <mdc_method> <sym_algo> <aead_algo>
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 2 {
                symmetricAlgorithm = parts[1]
            }
        } else if key == "PLAINTEXT" {
            // Format: PLAINTEXT <format> <timestamp> <filename>
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 3 {
                compressionAlgorithm = parts[0]
                timestamp = parts[1]
                filename = parts[2]
            }
        } else if key == "PLAINTEXT_LENGTH" {
            plaintextLength = Int(value)
        } else if key == "SYM_CREATED" {
            isSymmetric = true
            status = "decryption ok"
        } else if key == "NEWSIG" {
            // Only sent in gpg2 - start of signature verification
            return
        } else if key == "GOODSIG" {
            // Format: GOODSIG <long_keyid> <username>
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count >= 2 {
                signatureInfo["keyid"] = parts[0]
                signatureInfo["username"] = parts[1]
                signatureInfo["status"] = "signature good"
            }
        } else if key == "BADSIG" {
            // Format: BADSIG <long_keyid> <username>
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count >= 2 {
                signatureInfo["keyid"] = parts[0]
                signatureInfo["username"] = parts[1]
                signatureInfo["status"] = "signature bad"
            }
        } else if key == "ERRSIG" {
            // Format: ERRSIG <long_keyid> <pubkey_algo> <hash_algo> <sig_class> <timestamp> <rc> [<fingerprint>]
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 6 {
                signatureInfo["keyid"] = parts[0]
                signatureInfo["timestamp"] = parts[4]
                signatureInfo["status"] = "signature error"
                if parts.count >= 7 {
                    signatureInfo["fingerprint"] = parts[6]
                }
            }
        } else if key == "VALIDSIG" {
            // Format: VALIDSIG <fingerprint> <sig_creation_date> <sig-timestamp> <expire-timestamp> ...
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 4 {
                signatureInfo["fingerprint"] = parts[0]
                signatureInfo["creation_date"] = parts[1]
                signatureInfo["timestamp"] = parts[2]
                signatureInfo["expiry"] = parts[3]
                signatureInfo["status"] = "signature valid"
            }
        } else if key == "TRUST_ULTIMATE" || key == "TRUST_FULLY" || key == "TRUST_MARGINAL" || 
                  key == "TRUST_NEVER" || key == "TRUST_UNDEFINED" || key == "TRUST_EXPIRED" {
            signatureInfo["trust_level"] = key
        } else if key == "NO_PUBKEY" {
            signatureInfo["keyid"] = value
            signatureInfo["status"] = "no public key"
        } else if key == "KEYEXPIRED" || key == "KEYREVOKED" {
            signatureInfo["status"] = key == "KEYEXPIRED" ? "key expired" : "key revoked"
        } else if ["BEGIN_SIGNING", "SIG_CREATED", "KEY_CONSIDERED"].contains(key) {
            // These are informational and don't affect decryption status
            return
        } else {
            // Debug logging removed
        }
    }
    
    /// Whether the decrypted message has a valid signature
    public var hasValidSignature: Bool {
        guard let sigStatus = signatureInfo["status"] as? String else { return false }
        return sigStatus == "signature good" || sigStatus == "signature valid"
    }
    
    /// Get a summary of decryption results
    public var summary: String {
        var parts: [String] = []
        
        if isSuccessful {
            parts.append("Decryption successful")
            
            if isSymmetric {
                parts.append("Type: Symmetric")
            } else if keyId != nil {
                parts.append("Type: Public Key")
            }
            
            if let sigStatus = signatureInfo["status"] as? String {
                parts.append("Signature: \(sigStatus)")
            }
            
        } else {
            if let status = status {
                parts.append("Decryption failed: \(status)")
            } else {
                parts.append("Decryption failed")
            }
        }
        
        return parts.joined(separator: ", ")
    }
}
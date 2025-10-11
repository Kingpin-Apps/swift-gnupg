import Foundation

/// Handles status messages during encryption operations
public final class EncryptResult: BaseStatusHandler, @unchecked Sendable {
    
    // MARK: - Properties
    
    public var recipients: [String: [String: Any]] = [:]
    public var invalidRecipients: [[String: Any]] = []
    public var status: String?
    public var encryptionType: String?
    public var symmetricAlgorithm: String?
    public var compressionAlgorithm: String?
    public var publicKeyAlgorithm: String?
    
    // Logger removed for initial implementation
    
    public override init(gpg: GnuPG) {
        super.init(gpg: gpg)
    }
    
    /// Whether the encryption operation was successful
    public var isSuccessful: Bool {
        return status == "encryption ok" && invalidRecipients.isEmpty
    }
    
    public override func handleStatus(key: String, value: String) {
        if key == "WARNING" || key == "ERROR" || key == "FAILURE" {
            // Warning logging removed
            if status == nil {
                status = "\(key.lowercased()): \(value)"
            }
        } else if key == "BEGIN_ENCRYPTION" {
            status = "encryption started"
        } else if key == "END_ENCRYPTION" {
            status = "encryption ok"
        } else if key == "INV_RECP" {
            // Invalid recipient
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            let reason = parts.count > 0 ? parts[0] : "unknown"
            let recipient = parts.count > 1 ? parts[1] : value
            
            invalidRecipients.append([
                "reason": reason,
                "recipient": recipient,
                "status": "invalid recipient"
            ])
            
            if status == nil {
                status = "invalid recipient"
            }
        } else if key == "NO_RECP" {
            status = "no recipients specified"
        } else if key == "KEYEXPIRED" {
            status = "recipient key expired"
        } else if key == "KEYREVOKED" {
            status = "recipient key revoked"
        } else if key == "SIGEXPIRED" {
            status = "signature expired"
        } else if key == "BAD_PASSPHRASE" {
            status = "bad passphrase"
        } else if key == "GOOD_PASSPHRASE" {
            // Informational - symmetric encryption passphrase is good
            return
        } else if key == "NEED_PASSPHRASE" {
            // Informational - need passphrase for symmetric encryption
            return
        } else if key == "USERID_HINT" {
            // Format: USERID_HINT <long_keyid> <email_or_name>
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count >= 2 {
                let keyId = parts[0]
                let hint = parts[1]
                
                if recipients[keyId] == nil {
                    recipients[keyId] = [:]
                }
                recipients[keyId]?["hint"] = hint
            }
        } else if key == "ENCRYPTION_COMPLIANCE_MODE" {
            encryptionType = value
        } else if key == "SYM_CREATED" {
            status = "encryption ok"
            encryptionType = "symmetric"
        } else if key == "PKA_TRUST_GOOD" || key == "PKA_TRUST_BAD" {
            // PKA (Public Key Association) trust information
            // This is informational and doesn't affect encryption success
            return
        } else if key == "PLAINTEXT" {
            // Information about the plaintext being encrypted
            // Format: PLAINTEXT <format> <timestamp> <filename>
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 1 {
                // Store compression/format information
                compressionAlgorithm = parts[0]
            }
        } else if key == "PLAINTEXT_LENGTH" {
            // Length of plaintext - informational
            return
        } else if ["BEGIN_SIGNING", "SIG_CREATED", "KEY_CONSIDERED"].contains(key) {
            // These can occur during encrypt-and-sign operations
            // They're informational and don't affect encryption status
            return
        } else if key == "NEWSIG" {
            // Only sent in gpg2 for signing operations
            return
        } else {
            // Debug logging removed
        }
    }
    
    /// Get a summary of encryption results
    public var summary: String {
        var parts: [String] = []
        
        if isSuccessful {
            parts.append("Encryption successful")
            
            if !recipients.isEmpty {
                parts.append("Recipients: \(recipients.count)")
            }
            
            if encryptionType == "symmetric" {
                parts.append("Type: Symmetric")
            } else if !recipients.isEmpty {
                parts.append("Type: Public Key")
            }
            
        } else {
            if let status = status {
                parts.append("Encryption failed: \(status)")
            } else {
                parts.append("Encryption failed")
            }
            
            if !invalidRecipients.isEmpty {
                parts.append("Invalid recipients: \(invalidRecipients.count)")
            }
        }
        
        return parts.joined(separator: ", ")
    }
}
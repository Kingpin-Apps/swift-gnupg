import Foundation

/// Handles status messages during signing operations
public final class SignResult: BaseStatusHandler, @unchecked Sendable {
    
    // MARK: - Properties
    
    public var type: String?
    public var hashAlgo: String?
    public var fingerprint: String?
    public var status: String?
    public var statusDetail: String?
    public var keyId: String?
    public var username: String?
    public var timestamp: String?
    
    // Logger removed for initial implementation
    
    public override init(gpg: GnuPG) {
        super.init(gpg: gpg)
    }
    
    /// Whether the signing operation was successful
    public var isSuccessful: Bool {
        return fingerprint != nil && status == "signature created"
    }
    
    /// Whether the signing result is valid (alias for isSuccessful)
    public var isValid: Bool {
        return isSuccessful && status != "bad passphrase" && status != "invalid signer"
    }
    
    public override func handleStatus(key: String, value: String) {
        if key == "WARNING" || key == "ERROR" || key == "FAILURE" {
            // Warning logging removed
            if status == nil {
                status = "\(key.lowercased()): \(value)"
            }
        } else if key == "KEYEXPIRED" || key == "SIGEXPIRED" {
            status = "key expired"
        } else if key == "KEYREVOKED" {
            status = "key revoked"
        } else if key == "SIG_CREATED" {
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 6 {
                type = parts[0]
                // parts[1] is algorithm number
                hashAlgo = parts[2]
                // parts[3] is class
                timestamp = parts[4]
                fingerprint = parts[5]
                status = "signature created"
            }
        } else if key == "USERID_HINT" {
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count >= 2 {
                keyId = parts[0]
                username = parts[1]
            }
        } else if key == "BAD_PASSPHRASE" {
            status = "bad passphrase"
        } else if key == "INV_SGNR" || key == "INV_RECP" {
            // INV_RECP is returned in older versions
            if status == nil {
                status = "invalid signer"
            } else {
                status = "invalid signer: \(status!)"
            }
            statusDetail = value // Could be enhanced to parse invalid recipient details
        } else if ["NEED_PASSPHRASE", "GOOD_PASSPHRASE", "BEGIN_SIGNING"].contains(key) {
            // These are informational messages, don't affect status
            return
        } else {
            // Debug logging removed
        }
    }
}
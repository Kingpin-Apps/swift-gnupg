import Foundation

/// Handles status messages during signature verification
public final class VerifyResult: BaseStatusHandler, @unchecked Sendable {
    
    // MARK: - Trust Levels
    
    public static let trustExpired = 0
    public static let trustUndefined = 1  
    public static let trustNever = 2
    public static let trustMarginal = 3
    public static let trustFully = 4
    public static let trustUltimate = 5
    
    public static let trustLevels: [String: Int] = [
        "TRUST_EXPIRED": trustExpired,
        "TRUST_UNDEFINED": trustUndefined,
        "TRUST_NEVER": trustNever,
        "TRUST_MARGINAL": trustMarginal,
        "TRUST_FULLY": trustFully,
        "TRUST_ULTIMATE": trustUltimate
    ]
    
    // MARK: - Error Codes
    
    public static let gpgSystemErrorCodes: [Int: String] = [
        1: "permission denied",
        35: "file exists", 
        81: "file not found",
        97: "not a directory"
    ]
    
    public static let gpgErrorCodes: [Int: String] = [
        11: "incorrect passphrase"
    ]
    
    // MARK: - Properties
    
    public var valid: Bool = false
    public var fingerprint: String?
    public var creationDate: String?
    public var timestamp: String?
    public var signatureId: String?
    public var keyId: String?
    public var username: String?
    public var keyStatus: String?
    public var status: String?
    public var pubkeyFingerprint: String?
    public var expireTimestamp: String?
    public var sigTimestamp: String?
    public var trustText: String?
    public var trustLevel: Int?
    public var sigInfo: [String: [String: Any]] = [:]
    public var problems: [[String: Any]] = []
    
    // Logger removed for initial implementation
    
    public override init(gpg: GnuPG) {
        super.init(gpg: gpg)
    }
    
    /// Helper function to update signature info
    private func updateSigInfo(_ updates: [String: Any]) {
        guard let sigId = signatureId else {
            // Debug logging removed
            return
        }
        
        if sigInfo[sigId] == nil {
            sigInfo[sigId] = [:]
        }
        
        for (key, value) in updates {
            sigInfo[sigId]?[key] = value
        }
    }
    
    public override func handleStatus(key: String, value: String) {
        if VerifyResult.trustLevels.keys.contains(key) {
            trustText = key
            trustLevel = VerifyResult.trustLevels[key]
            updateSigInfo(["trust_level": trustLevel as Any, "trust_text": trustText as Any])
            // Clear signature ID after processing trust level
            signatureId = nil
        } else if key == "WARNING" || key == "ERROR" {
            // Warning logging removed
        } else if key == "BADSIG" {
            valid = false
            status = "signature bad"
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count >= 2 {
                keyId = parts[0]
                username = parts[1]
                problems.append(["status": status!, "keyid": keyId!, "user": username!])
                updateSigInfo(["keyid": keyId!, "username": username!, "status": status!])
            }
        } else if key == "ERRSIG" {
            valid = false
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 5 {
                keyId = parts[0]
                timestamp = parts[4]
                // Since GnuPG 2.2.7, a fingerprint is included
                if parts.count >= 7 {
                    fingerprint = parts[6]
                }
                status = "signature error"
                updateSigInfo([
                    "keyid": keyId!,
                    "timestamp": timestamp!,
                    "fingerprint": fingerprint as Any,
                    "status": status!
                ])
                problems.append([
                    "status": status!,
                    "keyid": keyId!,
                    "timestamp": timestamp!,
                    "fingerprint": fingerprint as Any
                ])
            }
        } else if key == "EXPSIG" {
            valid = false
            status = "signature expired"
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count >= 2 {
                keyId = parts[0]
                username = parts[1]
                updateSigInfo(["keyid": keyId!, "username": username!, "status": status!])
                problems.append(["status": status!, "keyid": keyId!, "user": username!])
            }
        } else if key == "GOODSIG" {
            valid = true
            status = "signature good"
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count >= 2 {
                keyId = parts[0]
                username = parts[1]
                updateSigInfo(["keyid": keyId!, "username": username!, "status": status!])
            }
        } else if key == "VALIDSIG" {
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 4 {
                fingerprint = parts[0]
                creationDate = parts[1]
                sigTimestamp = parts[2]
                expireTimestamp = parts[3]
                // May be different if signature is made with a subkey
                if parts.count >= 10 {
                    pubkeyFingerprint = parts[9]
                }
                status = "signature valid"
                updateSigInfo([
                    "fingerprint": fingerprint!,
                    "creation_date": creationDate!,
                    "timestamp": sigTimestamp!,
                    "expiry": expireTimestamp!,
                    "pubkey_fingerprint": pubkeyFingerprint as Any,
                    "status": status!
                ])
            }
        } else if key == "SIG_ID" {
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 3 {
                let sigId = parts[0]
                let creationDate = parts[1]
                let timestamp = parts[2]
                sigInfo[sigId] = ["creation_date": creationDate, "timestamp": timestamp]
                signatureId = sigId
                self.creationDate = creationDate
                self.timestamp = timestamp
            }
        } else if key == "NO_PUBKEY" {
            valid = false
            keyId = value
            status = "no public key"
            problems.append(["status": status!, "keyid": keyId!])
        } else if key == "NO_SECKEY" {
            valid = false
            keyId = value
            status = "no secret key" 
            problems.append(["status": status!, "keyid": keyId!])
        } else if key == "EXPKEYSIG" || key == "REVKEYSIG" {
            valid = false
            let parts = value.split(separator: " ", maxSplits: 1).map(String.init)
            if parts.count >= 2 {
                keyId = parts[0]
                username = parts[1]
                keyStatus = key == "EXPKEYSIG" ? "signing key has expired" : "signing key was revoked"
                status = keyStatus
                updateSigInfo(["keyid": keyId!, "username": username!, "status": status!])
                problems.append(["status": status!, "keyid": keyId!, "user": username!])
            }
        } else if key == "UNEXPECTED" || key == "FAILURE" {
            valid = false
            if key == "UNEXPECTED" {
                status = "unexpected data"
            } else {
                // Handle failure with error codes
                let message = "error - \(value)"
                let parts = value.split(separator: " ")
                if let lastPart = parts.last,
                   let code = Int(lastPart) {
                    let systemError = (code & 0x8000) != 0
                    let errorCode = code & 0x7FFF
                    
                    if systemError {
                        if let errorMessage = VerifyResult.gpgSystemErrorCodes[errorCode] {
                            let operation = parts.dropLast().joined(separator: " ")
                            status = "\(operation): \(errorMessage)"
                        }
                    } else {
                        if let errorMessage = VerifyResult.gpgErrorCodes[errorCode] {
                            let operation = parts.dropLast().joined(separator: " ")
                            status = "\(operation): \(errorMessage)"
                        }
                    }
                }
                if status == nil {
                    status = message
                }
            }
        } else if key == "NODATA" {
            valid = false
            status = "signature expected but not found"
        } else if ["DECRYPTION_INFO", "PLAINTEXT", "PLAINTEXT_LENGTH", "BEGIN_SIGNING", "KEY_CONSIDERED"].contains(key) {
            // These are informational and don't affect validity
            return
        } else if key == "NEWSIG" {
            // Only sent in gpg2. Clear any signature ID
            signatureId = nil
        } else {
            // Debug logging removed
        }
    }
}
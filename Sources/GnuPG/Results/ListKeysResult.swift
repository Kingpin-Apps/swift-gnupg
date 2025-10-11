import Foundation

/// Represents information about a GPG key
public struct GPGKey: Codable, Sendable {
    public let type: String              // "pub", "sec", "sub", "uid", etc.
    public let trustLevel: String?       // Trust level (ultimate, full, marginal, etc.)
    public let keyLength: Int?           // Key length in bits
    public let algorithm: String?        // Key algorithm
    public let keyId: String             // Key ID
    public let creationDate: String?     // Creation date
    public let expirationDate: String?  // Expiration date
    public let userId: String?           // User ID
    public let fingerprint: String?      // Key fingerprint
    public let capabilities: String?     // Key capabilities (S=sign, C=certify, E=encrypt, A=authenticate)
    
    // Additional properties for compatibility
    public var userIds: [String] { [userId].compactMap { $0 } }
    public var ownertrust: String { trustLevel ?? "-" }
    public var subkeys: [(String, String, String, String?)] { [] } // (keyId, capability, fingerprint, keygrip)
    public var keygrip: String? { nil } // Keygrip for compatibility
    public var subkeyInfo: [[String: Any]]? { nil } // Subkey info for compatibility
    public var expires: Date? {
        guard let expDate = expirationDate,
              !expDate.isEmpty,
              expDate != "0",
              let timestamp = TimeInterval(expDate) else {
            return nil
        }
        return Date(timeIntervalSince1970: timestamp)
    }
    
    public init(type: String, trustLevel: String?, keyLength: Int?, algorithm: String?,
                keyId: String, creationDate: String?, expirationDate: String?,
                userId: String?, fingerprint: String?, capabilities: String?) {
        self.type = type
        self.trustLevel = trustLevel
        self.keyLength = keyLength
        self.algorithm = algorithm
        self.keyId = keyId
        self.creationDate = creationDate
        self.expirationDate = expirationDate
        self.userId = userId
        self.fingerprint = fingerprint
        self.capabilities = capabilities
    }
    
    /// Whether this key is expired
    public var isExpired: Bool {
        guard let expDate = expirationDate,
              !expDate.isEmpty,
              expDate != "0",
              let timestamp = TimeInterval(expDate) else {
            return false
        }
        return Date() > Date(timeIntervalSince1970: timestamp)
    }
    
    /// Whether this key is a primary key
    public var isPrimaryKey: Bool {
        return type == "pub" || type == "sec"
    }
    
    /// Whether this key is for signing
    public var canSign: Bool {
        return capabilities?.contains("S") == true
    }
    
    /// Whether this key is for encryption
    public var canEncrypt: Bool {
        return capabilities?.contains("E") == true
    }
    
    /// Whether this key is for certification
    public var canCertify: Bool {
        return capabilities?.contains("C") == true
    }
}

/// Handles key listing operations
public final class ListKeysResult: BaseStatusHandler, @unchecked Sendable {
    
    // MARK: - Properties
    
    public var keys: [GPGKey] = []
    public var status: String?
    
    private var currentKey: GPGKey?
    private var currentKeyType: String?
    private var currentTrustLevel: String?
    private var currentKeyLength: Int?
    private var currentAlgorithm: String?
    private var currentKeyId: String?
    private var currentCreationDate: String?
    private var currentExpirationDate: String?
    private var currentCapabilities: String?
    private var currentFingerprint: String?
    private var currentUserId: String?
    
    // Logger removed for initial implementation
    
    public override init(gpg: GnuPG) {
        super.init(gpg: gpg)
    }
    
    /// Whether the key listing operation was successful
    public var isSuccessful: Bool {
        return status == "key listing ok" || !keys.isEmpty
    }
    
    /// Parse the colon-delimited output format from GPG
    public func parseColonOutput(_ output: String) {
        let lines = output.components(separatedBy: .newlines)
        
        for line in lines {
            if line.isEmpty { continue }
            
            let fields = line.components(separatedBy: ":")
            guard fields.count >= 10 else { continue }
            
            let recordType = fields[0]
            
            switch recordType {
            case "pub", "sec": // Public/Secret primary key
                finalizePreviousKey()
                currentKeyType = recordType
                currentTrustLevel = fields[1]
                currentKeyLength = Int(fields[2])
                currentAlgorithm = fields[3]
                currentKeyId = fields[4]
                currentCreationDate = fields[5]
                currentExpirationDate = fields[6]
                currentCapabilities = fields.count > 12 ? fields[12] : ""
                currentFingerprint = nil
                currentUserId = nil
                
            case "fpr": // Fingerprint - comes after pub/sec record
                if currentKeyId != nil {
                    currentFingerprint = fields.count > 9 ? fields[9] : ""
                    maybeCreateKey()
                }
                
            case "uid": // User ID - comes after fpr record
                if currentKeyId != nil {
                    currentUserId = fields.count > 9 ? fields[9] : ""
                    maybeCreateKey()
                }
                
            case "sub": // Subkey
                finalizePreviousKey()
                let subkeyId = fields[4]
                let subkey = GPGKey(
                    type: recordType,
                    trustLevel: fields[1],
                    keyLength: Int(fields[2]),
                    algorithm: fields[3],
                    keyId: subkeyId,
                    creationDate: fields[5],
                    expirationDate: fields[6],
                    userId: nil,
                    fingerprint: nil,
                    capabilities: fields.count > 12 ? fields[12] : ""
                )
                keys.append(subkey)
                
            default:
                // Skip other record types for now
                break
            }
        }
        
        finalizePreviousKey()
        status = "key listing ok"
    }
    
    private func maybeCreateKey() {
        // Create the key if we have enough data and haven't created it yet
        if let keyId = currentKeyId,
           let keyType = currentKeyType,
           currentKey == nil,
           currentUserId != nil { // Wait for user ID to create the key
            
            let key = GPGKey(
                type: keyType,
                trustLevel: currentTrustLevel,
                keyLength: currentKeyLength,
                algorithm: currentAlgorithm,
                keyId: keyId,
                creationDate: currentCreationDate,
                expirationDate: currentExpirationDate,
                userId: currentUserId,
                fingerprint: currentFingerprint,
                capabilities: currentCapabilities
            )
            currentKey = key
        }
    }
    
    private func finalizePreviousKey() {
        if let key = currentKey {
            keys.append(key)
            currentKey = nil
            // Reset current state
            currentKeyType = nil
            currentTrustLevel = nil
            currentKeyLength = nil
            currentAlgorithm = nil
            currentKeyId = nil
            currentCreationDate = nil
            currentExpirationDate = nil
            currentCapabilities = nil
            currentFingerprint = nil
            currentUserId = nil
        }
    }
    
    public override func handleStatus(key: String, value: String) {
        if key == "WARNING" || key == "ERROR" || key == "FAILURE" {
            if status == nil {
                status = "\(key.lowercased()): \(value)"
            }
        } else {
            // Most key listing doesn't use status messages
            // The main parsing is done via colon output format
        }
    }
    
    /// Get public keys only
    public var publicKeys: [GPGKey] {
        return keys.filter { $0.type == "pub" }
    }
    
    /// Get secret keys only
    public var secretKeys: [GPGKey] {
        return keys.filter { $0.type == "sec" }
    }
    
    /// Find a key by ID or fingerprint
    public func findKey(byId identifier: String) -> GPGKey? {
        return keys.first { key in
            key.keyId.hasSuffix(identifier) || 
            key.fingerprint?.contains(identifier) == true
        }
    }
    
    /// Get all fingerprints from the keys
    public var fingerprints: [String] {
        return keys.compactMap { $0.fingerprint }
    }
    
    /// Key map for compatibility (maps fingerprint to key)
    public var keyMap: [String: GPGKey] {
        var map: [String: GPGKey] = [:]
        for key in keys {
            if let fingerprint = key.fingerprint {
                map[fingerprint] = key
            }
        }
        return map
    }
    
    /// Get a summary of the key listing results
    public var summary: String {
        if isSuccessful {
            let pubCount = publicKeys.count
            let secCount = secretKeys.count
            return "Found \(pubCount) public keys, \(secCount) secret keys"
        } else {
            return "Key listing failed: \(status ?? "unknown error")"
        }
    }
}
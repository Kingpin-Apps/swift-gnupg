import Foundation

/// Represents a subkey nested under a primary key.
public struct GPGSubkey: Codable, Sendable {
    public let keyId: String
    public let capabilities: String
    public let fingerprint: String
    public let keygrip: String?

    public init(keyId: String, capabilities: String, fingerprint: String, keygrip: String?) {
        self.keyId = keyId
        self.capabilities = capabilities
        self.fingerprint = fingerprint
        self.keygrip = keygrip
    }
}

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
    public let ownerTrust: String?       // Owner trust value (separate from calculated validity/trustLevel)
    public let keygrip: String?          // Keygrip of the primary key (requires --with-keygrip)
    public let subkeyList: [GPGSubkey]   // Subkeys nested under this primary key

    // Additional properties for compatibility
    public var userIds: [String] { [userId].compactMap { $0 } }
    public var ownertrust: String { ownerTrust ?? "-" }
    /// Subkeys as (keyId, capability, fingerprint, keygrip) tuples.
    public var subkeys: [(String, String, String, String?)] {
        subkeyList.map { ($0.keyId, $0.capabilities, $0.fingerprint, $0.keygrip) }
    }
    public var subkeyInfo: [[String: Any]]? {
        subkeyList.isEmpty ? nil : subkeyList.map {
            ["keyid": $0.keyId, "cap": $0.capabilities, "fingerprint": $0.fingerprint, "keygrip": $0.keygrip ?? ""]
        }
    }
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
                userId: String?, fingerprint: String?, capabilities: String?,
                ownerTrust: String? = nil, keygrip: String? = nil,
                subkeyList: [GPGSubkey] = []) {
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
        self.ownerTrust = ownerTrust
        self.keygrip = keygrip
        self.subkeyList = subkeyList
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
    private var currentOwnerTrust: String?
    private var currentKeygrip: String?

    // Accumulators for the subkeys of the current primary key.
    private var currentSubkeys: [GPGSubkey] = []
    private var subId: String?
    private var subCapabilities: String = ""
    private var subFingerprint: String = ""
    private var subKeygrip: String?
    
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
                // Field 9 (index 8) is ownertrust; field 12 (index 11) is the
                // key-capabilities string.
                currentOwnerTrust = fields.count > 8 ? fields[8] : nil
                currentCapabilities = fields.count > 11 ? fields[11] : ""
                currentFingerprint = nil
                currentUserId = nil

            case "fpr": // Fingerprint - applies to the primary or current subkey
                let value = fields.count > 9 ? fields[9] : ""
                if subId != nil {
                    subFingerprint = value
                } else if currentKeyId != nil {
                    currentFingerprint = value
                }

            case "grp": // Keygrip - applies to the primary or current subkey
                let value = fields.count > 9 ? fields[9] : ""
                if subId != nil {
                    subKeygrip = value
                } else if currentKeyId != nil {
                    currentKeygrip = value
                }

            case "uid": // User ID - comes after the primary's fpr/grp records
                if currentKeyId != nil, currentUserId == nil {
                    currentUserId = ListKeysResult.unescapeUserId(fields.count > 9 ? fields[9] : "")
                }

            case "sub", "ssb": // Subkey (public/secret) - nested under the primary
                finalizeCurrentSubkey()
                subId = fields[4]
                subCapabilities = fields.count > 11 ? fields[11] : ""
                subFingerprint = ""
                subKeygrip = nil

            default:
                // Skip other record types for now
                break
            }
        }

        finalizePreviousKey()
        status = "key listing ok"
    }

    /// Parse the colon output of `--search-keys`, which uses a different and
    /// shorter record layout than `--list-keys`:
    ///
    ///   info:<version>:<count>
    ///   pub:<keyid|fpr>:<algo>:<keylen>:<created>:<expires>:<flags>
    ///   uid:<escaped uid>:<created>:<expires>
    ///
    /// A `pub` with no following `uid` lines (some keyservers strip UIDs) still
    /// yields one key; a `pub` with multiple UIDs yields one entry per UID so
    /// `keys.first { $0.userIds.contains(...) }` works.
    public func parseSearchOutput(_ output: String) {
        var pendingKeyId: String?
        var pendingAlgo: String?
        var pendingLen: Int?
        var pendingCreated: String?
        var pendingUids: [String] = []

        func flush() {
            guard let keyId = pendingKeyId else { return }
            let fingerprint = keyId.count >= 32 ? keyId : nil
            let make: (String?) -> GPGKey = { uid in
                GPGKey(type: "pub", trustLevel: nil, keyLength: pendingLen,
                       algorithm: pendingAlgo, keyId: keyId, creationDate: pendingCreated,
                       expirationDate: nil, userId: uid, fingerprint: fingerprint, capabilities: nil)
            }
            if pendingUids.isEmpty {
                keys.append(make(nil))
            } else {
                for uid in pendingUids { keys.append(make(uid)) }
            }
            pendingKeyId = nil; pendingAlgo = nil; pendingLen = nil
            pendingCreated = nil; pendingUids = []
        }

        for line in output.components(separatedBy: .newlines) {
            if line.isEmpty { continue }
            let fields = line.components(separatedBy: ":")
            switch fields[0] {
            case "pub":
                flush()
                pendingKeyId = fields.count > 1 ? fields[1] : nil
                pendingAlgo = fields.count > 2 ? fields[2] : nil
                pendingLen = fields.count > 3 ? Int(fields[3]) : nil
                pendingCreated = fields.count > 4 ? fields[4] : nil
            case "uid":
                if fields.count > 1 {
                    pendingUids.append(ListKeysResult.unescapeUserId(fields[1]))
                }
            default:
                break
            }
        }
        flush()
        status = "search completed"
    }

    /// Append the in-progress subkey (if any) to the current primary's list.
    private func finalizeCurrentSubkey() {
        if let id = subId {
            currentSubkeys.append(GPGSubkey(
                keyId: id,
                capabilities: subCapabilities,
                fingerprint: subFingerprint,
                keygrip: (subKeygrip?.isEmpty == false) ? subKeygrip : nil
            ))
            subId = nil
            subCapabilities = ""
            subFingerprint = ""
            subKeygrip = nil
        }
    }

    /// Decode GnuPG's colon-format escaping in a user ID. GnuPG emits `\xNN`
    /// hex escapes (e.g. `\x3a` for ':') and the C-style escapes `\n \r \f \v
    /// \b \0`. This mirrors python-gnupg's two-pass unescaping.
    static func unescapeUserId(_ uid: String) -> String {
        guard uid.contains("\\") else { return uid }

        // Pass 1: \xNN -> the corresponding character.
        var result = ""
        let chars = Array(uid)
        var i = 0
        while i < chars.count {
            if chars[i] == "\\", i + 3 < chars.count, chars[i + 1] == "x",
               let byte = UInt8(String(chars[i + 2...i + 3]), radix: 16) {
                result.append(Character(UnicodeScalar(byte)))
                i += 4
            } else {
                result.append(chars[i])
                i += 1
            }
        }

        // Pass 2: basic C-style escapes.
        let basicEscapes: [(String, Character)] = [
            ("\\n", "\n"), ("\\r", "\r"), ("\\f", "\u{0C}"),
            ("\\v", "\u{0B}"), ("\\b", "\u{08}"), ("\\0", "\u{00}")
        ]
        for (escaped, char) in basicEscapes {
            result = result.replacingOccurrences(of: escaped, with: String(char))
        }
        return result
    }
    
    private func finalizePreviousKey() {
        // Flush any in-progress subkey into the current primary first.
        finalizeCurrentSubkey()

        if let keyId = currentKeyId, let keyType = currentKeyType {
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
                capabilities: currentCapabilities,
                ownerTrust: currentOwnerTrust,
                keygrip: currentKeygrip,
                subkeyList: currentSubkeys
            )
            keys.append(key)
        }

        // Reset all per-primary state.
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
        currentOwnerTrust = nil
        currentKeygrip = nil
        currentSubkeys = []
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

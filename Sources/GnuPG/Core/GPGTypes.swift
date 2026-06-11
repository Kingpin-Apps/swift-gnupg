import Foundation

// MARK: - GPG Version

/// GPG version information
public struct GPGVersion: Sendable {
    public let major: Int
    public let minor: Int  
    public let patch: Int?
    
    public init(major: Int, minor: Int, patch: Int? = nil) {
        self.major = major
        self.minor = minor
        self.patch = patch
    }
    
    static func parse(from data: Data) -> GPGVersion? {
        // Decode with Latin-1 (the library's default encoding), not ASCII:
        // `--list-config` output can contain bytes > 127 (locale-dependent
        // fields), and `.ascii` fails the whole decode on any such byte, leaving
        // the version unparsed (observed on Linux). Latin-1 maps every byte.
        guard let string = String(data: data, encoding: .isoLatin1),
              let range = string.range(of: #"cfg:version:(\d+(?:\.\d+)*)"#, options: .regularExpression) else {
            return nil
        }
        
        let versionString = String(string[range]).replacingOccurrences(of: "cfg:version:", with: "")
        let components = versionString.split(separator: ".").compactMap { Int($0) }
        
        guard components.count >= 2 else { return nil }
        
        return GPGVersion(
            major: components[0],
            minor: components[1], 
            patch: components.count > 2 ? components[2] : nil
        )
    }
}

extension GPGVersion: Comparable {
    public static func < (lhs: GPGVersion, rhs: GPGVersion) -> Bool {
        if lhs.major != rhs.major {
            return lhs.major < rhs.major
        }
        if lhs.minor != rhs.minor {
            return lhs.minor < rhs.minor
        }
        return (lhs.patch ?? 0) < (rhs.patch ?? 0)
    }
    
    public static func == (lhs: GPGVersion, rhs: GPGVersion) -> Bool {
        return lhs.major == rhs.major && lhs.minor == rhs.minor && lhs.patch == rhs.patch
    }
}

// MARK: - GPG Trust Levels

/// Trust levels for GPG keys
public enum GPGTrust: String, CaseIterable, Equatable, Sendable {
    case undefined = "q"       // Unknown trust
    case never = "n"           // Never trust
    case marginal = "m"        // Marginal trust
    case fully = "f"           // Full trust
    case ultimate = "u"        // Ultimate trust
    case expired = "e"         // Key expired
    case revoked = "r"         // Key revoked
    case disabled = "d"        // Key disabled
    case unknown = "-"         // No trust value assigned
    
    public init(from string: String) {
        switch string {
        case "q": self = .undefined
        case "n": self = .never
        case "m": self = .marginal
        case "f": self = .fully
        case "u": self = .ultimate
        case "e": self = .expired
        case "r": self = .revoked
        case "d": self = .disabled
        case "-": self = .unknown
        default: self = .unknown // Default to unknown for invalid values
        }
    }
    
    /// Create a custom trust level for testing purposes
    public static func custom(_ value: String) -> GPGTrust {
        // Return closest match or unknown
        return GPGTrust(from: value)
    }

    /// The numeric ownertrust value understood by `gpg --import-ownertrust`,
    /// or `nil` for levels that can't be assigned as ownertrust (unknown,
    /// revoked, disabled). These mirror python-gnupg's `TRUST_LEVELS` + 1.
    public var ownertrustImportValue: Int? {
        switch self {
        case .expired:   return 1
        case .undefined: return 2
        case .never:     return 3
        case .marginal:  return 4
        case .fully:     return 5
        case .ultimate:  return 6
        case .unknown, .revoked, .disabled:
            return nil
        }
    }
}

// MARK: - GPG Errors

/// Errors that can occur during GPG operations
public enum GPGError: LocalizedError, Equatable {
    // MARK: - Initialization Errors
    case gpgNotAvailable(String)
    case invalidHomeDirecory(String)
    case unsupportedGPGVersion(GPGVersion, minimum: GPGVersion)
    case configurationError(String)
    
    // MARK: - Input/Output Errors
    case invalidInput(String)
    case invalidPassphrase(String)
    case fileNotFound(String)
    case fileAccessDenied(String)
    case permissionDenied(String)
    case diskFull
    case diskReadError(String)
    
    // MARK: - Process Errors
    case processLaunchFailed(String)
    case processTerminated(Int32, stderr: String)
    case processTimeout(timeoutSeconds: Double)
    case processInterrupted
    
    // MARK: - Key Management Errors
    case keyNotFound(String)
    case keyAlreadyExists(String)
    case keyExpired(String)
    case keyRevoked(String)
    case keyUntrusted(String)
    case invalidKeyData(String)
    case keyGenerationFailed(String)
    
    // MARK: - Cryptographic Operation Errors
    case signatureFailed(String)
    case verificationFailed(String)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case noValidRecipients([String])
    case badSignature(String)
    case expiredSignature(String)
    case noSecretKey(String)
    case noPublicKey(String)
    case noRecipients
    case invalidTrustLevel(String)
    
    // MARK: - Network/Communication Errors
    case keyserverError(String)
    case networkTimeout
    case networkUnavailable
    
    // MARK: - Generic Errors
    case unknownError(String)
    case internalError(String)
    
    public var errorDescription: String? {
        switch self {
        // MARK: - Initialization Errors
        case .gpgNotAvailable(let binary):
            return """
            GnuPG (gpg) not found in PATH.
            GPG binary not available: \(binary)
            Please install GPG or specify the correct path.
            
            Install via:
            • macOS: brew install gnupg
            • Ubuntu/Debian: sudo apt-get install gnupg
            • Other: https://gnupg.org/download/
            """
        case .invalidHomeDirecory(let path):
            return "GPG home directory is invalid or inaccessible: \(path)"
        case .unsupportedGPGVersion(let version, let minimum):
            return "GPG version \(version) is not supported. Minimum required version: \(minimum)"
        case .configurationError(let message):
            return "GPG configuration error: \(message)"
            
        // MARK: - Input/Output Errors
        case .invalidInput(let message):
            return "Invalid input: \(message)"
        case .invalidPassphrase(let reason):
            return "Invalid passphrase: \(reason)"
        case .fileNotFound(let path):
            return "File not found: \(path)"
        case .fileAccessDenied(let path):
            return "Access denied to file: \(path)"
        case .permissionDenied(let operation):
            return "Permission denied for operation: \(operation)"
        case .diskFull:
            return "Insufficient disk space for GPG operation"
        case .diskReadError(let path):
            return "Failed to read file: \(path)"
            
        // MARK: - Process Errors
        case .processLaunchFailed(let reason):
            return "Failed to launch GPG process: \(reason)"
        case .processTerminated(let code, let stderr):
            return "GPG process terminated with exit code \(code): \(stderr)"
        case .processTimeout(let timeoutSeconds):
            return "GPG operation timed out after \(timeoutSeconds) seconds"
        case .processInterrupted:
            return "GPG process was interrupted"
            
        // MARK: - Key Management Errors
        case .keyNotFound(let identifier):
            return "Key not found: \(identifier)"
        case .keyAlreadyExists(let identifier):
            return "Key already exists: \(identifier)"
        case .keyExpired(let identifier):
            return "Key has expired: \(identifier)"
        case .keyRevoked(let identifier):
            return "Key has been revoked: \(identifier)"
        case .keyUntrusted(let identifier):
            return "Key is not trusted: \(identifier)"
        case .invalidKeyData(let reason):
            return "Invalid key data: \(reason)"
        case .keyGenerationFailed(let reason):
            return "Key generation failed: \(reason)"
            
        // MARK: - Cryptographic Operation Errors
        case .signatureFailed(let reason):
            return "Signature creation failed: \(reason)"
        case .verificationFailed(let reason):
            return "Signature verification failed: \(reason)"
        case .encryptionFailed(let reason):
            return "Encryption failed: \(reason)"
        case .decryptionFailed(let reason):
            return "Decryption failed: \(reason)"
        case .noValidRecipients(let recipients):
            return "No valid recipients found: \(recipients.joined(separator: ", "))"
        case .badSignature(let details):
            return "Bad signature: \(details)"
        case .expiredSignature(let details):
            return "Signature has expired: \(details)"
        case .noSecretKey(let keyId):
            return "No secret key available for: \(keyId)"
        case .noPublicKey(let keyId):
            return "No public key available for: \(keyId)"
        case .noRecipients:
            return "No recipients specified for encryption"
        case .invalidTrustLevel(let level):
            return "Invalid trust level: \(level)"
            
        // MARK: - Network/Communication Errors
        case .keyserverError(let message):
            return "Keyserver error: \(message)"
        case .networkTimeout:
            return "Network operation timed out"
        case .networkUnavailable:
            return "Network is unavailable"
            
        // MARK: - Generic Errors
        case .unknownError(let message):
            return "Unknown error: \(message)"
        case .internalError(let message):
            return "Internal error: \(message)"
        }
    }
    
    /// User-friendly failure reason
    public var failureReason: String? {
        switch self {
        case .gpgNotAvailable:
            return "GPG is not installed or not in PATH"
        case .invalidPassphrase:
            return "The provided passphrase is invalid"
        case .processTerminated(let code, _):
            return "GPG operation failed with error code \(code)"
        case .keyNotFound:
            return "The requested key could not be found"
        case .signatureFailed, .verificationFailed:
            return "Cryptographic operation failed"
        case .encryptionFailed, .decryptionFailed:
            return "Encryption/decryption operation failed"
        case .networkTimeout, .networkUnavailable:
            return "Network connectivity issue"
        default:
            return "GPG operation failed"
        }
    }
    
    /// Recovery suggestions for the user
    public var recoverySuggestion: String? {
        switch self {
        case .gpgNotAvailable:
            return "Install GPG using 'brew install gnupg' or check your PATH configuration"
        case .invalidHomeDirecory:
            return "Create the GPG home directory or specify a valid existing directory"
        case .invalidPassphrase:
            return "Ensure the passphrase doesn't contain newline or null characters"
        case .fileNotFound:
            return "Check that the file exists and the path is correct"
        case .permissionDenied, .fileAccessDenied:
            return "Check file permissions and ensure you have read/write access"
        case .keyNotFound:
            return "Import the key first or check the key identifier"
        case .keyExpired:
            return "Renew the key or use a different key"
        case .noValidRecipients:
            return "Import the recipient's public key or check the recipient identifiers"
        case .networkTimeout, .networkUnavailable:
            return "Check your internet connection and try again"
        case .unsupportedGPGVersion:
            return "Upgrade to a newer version of GPG"
        default:
            return "Check the GPG configuration and try again"
        }
    }
}

// MARK: - Key Generation Parameters

/// Parameters for key generation
public class KeyGenParams {
    public var keyType: String?
    public var keyLength: Int?
    public var nameReal: String?
    public var nameComment: String?
    public var nameEmail: String?
    public var expire: String?
    public var passphrase: String?
    public var keyCurve: String?
    public var subkeyCurve: String?
    
    public init() {}
    
    public init(
        keyType: String? = nil,
        keyLength: Int? = nil,
        nameReal: String? = nil,
        nameComment: String? = nil,
        nameEmail: String? = nil,
        expire: String? = nil,
        passphrase: String? = nil
    ) {
        self.keyType = keyType
        self.keyLength = keyLength
        self.nameReal = nameReal
        self.nameComment = nameComment
        self.nameEmail = nameEmail
        self.expire = expire
        self.passphrase = passphrase
    }
}

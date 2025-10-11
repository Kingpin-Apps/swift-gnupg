# Swift GnuPG API Reference

@Metadata {
   @PageKind(article)
   @PageColor(purple)
   @Available(macOS, introduced: "10.15")
}

Comprehensive reference for all classes, methods, and types available in the Swift GnuPG library.

## Prerequisites

> Important: Before using any APIs, ensure you have:
> - **GnuPG 2.0+** installed and accessible (see <doc:GPGInstallation>)
> - **Swift GnuPG library** properly integrated (see <doc:GettingStarted>)

For troubleshooting common issues, see <doc:Troubleshooting>.

## Overview

This document provides a comprehensive reference for all classes, methods, and types available in the Swift GnuPG library.

## Table of Contents

- [GnuPG (Main Class)](#gnupg-main-class)
- [Result Classes](#result-classes)
- [Core Types](#core-types)
- [Error Types](#error-types)
- [Logging](#logging)

## GnuPG (Main Class)

The main class that provides the interface to GPG operations.

### Initialization

```swift
public init(
    gpgBinary: String = "gpg",
    gnupgHome: String? = nil,
    keyring: [String]? = nil,
    secretKeyring: [String]? = nil,
    verbose: Bool = false,
    useAgent: Bool = false,
    options: [String]? = nil,
    environment: [String: String]? = nil
) throws
```

**Parameters:**
- `gpgBinary`: Path to the GPG binary (defaults to "gpg")
- `gnupgHome`: Path to GPG home directory (defaults to GPG's default)
- `keyring`: Alternative keyring files to use
- `secretKeyring`: Alternative secret keyring files
- `verbose`: Enable verbose output
- `useAgent`: Whether to use GPG agent
- `options`: Additional GPG command-line options
- `environment`: Environment variables for GPG subprocess

**Throws:** `GPGError` if GPG binary is not available or configuration is invalid

### Properties

```swift
public let gpgBinary: String              // Path to GPG binary
public let gnupgHome: String?             // GPG home directory
public let verbose: Bool                  // Verbose mode flag
public let useAgent: Bool                 // GPG agent usage
public let keyring: [String]?             // Keyring files
public let secretKeyring: [String]?       // Secret keyring files
public let options: [String]?             // Additional options
public let environment: [String: String]? // Environment variables
public let encoding: String.Encoding      // Communication encoding (latin-1)
public var bufferSize: Int                // Buffer size for operations (16384)
public private(set) var version: GPGVersion? // Detected GPG version
public var checkFingerprintCollisions: Bool // Check for fingerprint collisions
public var logger: GPGLogger              // Logger instance
```

### Digital Signature Operations

#### Sign Message
```swift
public func sign(
    message: String,
    keyId: String? = nil,
    passphrase: String? = nil,
    clearsign: Bool = false,
    detach: Bool = false,
    armor: Bool = true,
    binary: Bool = false
) async -> SignResult
```

#### Sign Data
```swift
public func sign(
    data: Data,
    keyId: String? = nil,
    passphrase: String? = nil,
    clearsign: Bool = false,
    detach: Bool = false,
    armor: Bool = true,
    binary: Bool = false
) async -> SignResult
```

#### Sign File
```swift
public func signFile(
    filePath: String,
    keyId: String? = nil,
    passphrase: String? = nil,
    clearsign: Bool = false,
    detach: Bool = false,
    armor: Bool = true,
    binary: Bool = false,
    outputPath: String? = nil
) async -> SignResult
```

### Signature Verification Operations

#### Verify Message
```swift
public func verify(message: String) async -> VerifyResult
```

#### Verify Data
```swift
public func verify(data: Data) async -> VerifyResult
```

#### Verify File
```swift
public func verifyFile(
    filePath: String,
    signaturePath: String? = nil
) async -> VerifyResult
```

#### Convenience Methods
```swift
public func isSignatureValid(message: String) async -> Bool
public func isFileSignatureValid(filePath: String, signaturePath: String? = nil) async -> Bool
```

### Encryption Operations

#### Encrypt Message
```swift
public func encrypt(
    message: String,
    recipients: [String],
    sign: Bool = false,
    keyId: String? = nil,
    passphrase: String? = nil,
    armor: Bool = true,
    compress: Bool = true
) async -> EncryptResult
```

#### Encrypt Data
```swift
public func encrypt(
    data: Data,
    recipients: [String],
    sign: Bool = false,
    keyId: String? = nil,
    passphrase: String? = nil,
    armor: Bool = true,
    compress: Bool = true
) async -> EncryptResult
```

#### Encrypt File
```swift
public func encryptFile(
    filePath: String,
    recipients: [String],
    sign: Bool = false,
    keyId: String? = nil,
    passphrase: String? = nil,
    armor: Bool = true,
    compress: Bool = true,
    outputPath: String? = nil
) async -> EncryptResult
```

#### Symmetric Encryption
```swift
public func encryptSymmetric(
    message: String,
    passphrase: String,
    armor: Bool = true,
    compress: Bool = true
) async -> EncryptResult
```

### Decryption Operations

#### Decrypt Message
```swift
public func decrypt(
    message: String,
    passphrase: String? = nil
) async -> DecryptResult
```

#### Decrypt Data
```swift
public func decrypt(
    data: Data,
    passphrase: String? = nil
) async -> DecryptResult
```

#### Decrypt File
```swift
public func decryptFile(
    filePath: String,
    passphrase: String? = nil,
    outputPath: String? = nil
) async -> DecryptResult
```

#### Combined Decrypt and Verify
```swift
public func decryptAndVerify(
    message: String,
    passphrase: String? = nil
) async -> DecryptResult
```

#### Convenience Methods
```swift
public func canDecrypt(message: String) async -> Bool
public func canDecryptFile(filePath: String) async -> Bool
```

### Key Management Operations

#### List Keys
```swift
public func listKeys(
    secretKeys: Bool = false,
    keyIds: [String]? = nil,
    sigs: Bool = false
) async -> ListKeysResult
```

#### Import Keys
```swift
public func importKeys(keyString: String) async -> ImportResult
public func importKeys(keyData: Data) async -> ImportResult  
public func importKeysFromFile(filePath: String) async -> ImportResult
```

#### Export Keys
```swift
public func exportKeys(keyId: String? = nil, secretKeys: Bool = false) async -> Data?
public func exportKeysToFile(
    keyId: String? = nil,
    secretKeys: Bool = false,
    outputPath: String
) async -> Bool
```

#### Generate Keys
```swift
public func generateKey(
    keyType: String = "RSA",
    keySize: Int = 3072,
    userId: String,
    passphrase: String,
    expires: String = "0"
) async -> ImportResult
```

#### Delete Keys
```swift
public func deleteKey(keyId: String, secretKey: Bool = false) async -> Bool
```

#### Key Utilities
```swift
public func findKey(byIdentifier identifier: String) async -> GPGKey?
public func keyExists(keyId: String) async -> Bool
public func getKeyInfo(keyId: String) async -> GPGKey?
```

## Result Classes

### SignResult

Handles status messages during signing operations.

```swift
public final class SignResult: BaseStatusHandler {
    public var type: String?           // Signature type
    public var hashAlgo: String?       // Hash algorithm used
    public var fingerprint: String?    // Key fingerprint
    public var status: String?         // Operation status
    public var statusDetail: String?   // Status details
    public var keyId: String?          // Signing key ID
    public var username: String?       // Key username
    public var timestamp: String?      // Signature timestamp
    
    public var isSuccessful: Bool      // Whether signing succeeded
}
```

### VerifyResult

Handles status messages during verification operations.

```swift
public final class VerifyResult: BaseStatusHandler {
    public var valid: Bool = false           // Whether signature is valid
    public var fingerprint: String?         // Signer's fingerprint  
    public var creationDate: String?        // Signature creation date
    public var timestamp: String?           // Signature timestamp
    public var signatureId: String?         // Signature ID
    public var keyId: String?               // Signer's key ID
    public var username: String?            // Signer's username
    public var keyStatus: String?           // Key status
    public var status: String?              // Verification status
    public var trustText: String?           // Trust level text
    public var trustLevel: Int?             // Trust level number
    public var sigInfo: [String: [String: Any]] // Signature information
    public var problems: [[String: Any]]    // Verification problems
    
    // Trust level constants
    public static let trustExpired = 0
    public static let trustUndefined = 1
    public static let trustNever = 2
    public static let trustMarginal = 3
    public static let trustFully = 4
    public static let trustUltimate = 5
}
```

### EncryptResult

Handles status messages during encryption operations.

```swift
public final class EncryptResult: BaseStatusHandler {
    public var recipients: [String] = []     // Valid recipients
    public var invalidRecipients: [String] = [] // Invalid recipients
    public var status: String?               // Encryption status
    public var fingerprints: [String] = []   // Recipient fingerprints
    
    public var isSuccessful: Bool            // Whether encryption succeeded
    public func summary() -> String          // Summary of results
}
```

### DecryptResult

Handles status messages during decryption operations.

```swift
public final class DecryptResult: BaseStatusHandler {
    public var keyId: String?           // Decryption key ID
    public var fingerprint: String?     // Key fingerprint
    public var timestamp: String?       // Decryption timestamp
    public var signatureKeyId: String?  // Signature key ID (if signed)
    public var signatureFingerprint: String? // Signature fingerprint
    public var signatureTimestamp: String?   // Signature timestamp
    public var signatureUser: String?       // Signature username
    public var signatureValid: Bool = false // Whether signature is valid
    public var status: String?              // Decryption status
    
    public var isSuccessful: Bool           // Whether decryption succeeded
    public func summary() -> String         // Summary of results
}
```

### ListKeysResult

Handles key listing operations and contains GPGKey objects.

```swift
public final class ListKeysResult: BaseStatusHandler {
    public var keys: [GPGKey] = []      // All parsed keys
    public var status: String?          // Operation status
    
    public var isSuccessful: Bool       // Whether listing succeeded
    public var publicKeys: [GPGKey]     // Public keys only
    public var secretKeys: [GPGKey]     // Secret keys only
    public var summary: String          // Summary of results
    
    public func findKey(byId identifier: String) -> GPGKey? // Find key
    public func parseColonOutput(_ output: String)          // Parse GPG output
}
```

### GPGKey

Represents a GPG key with all its properties.

```swift
public struct GPGKey: Codable, Sendable {
    public let type: String              // "pub", "sec", "sub", etc.
    public let trustLevel: String?       // Trust level
    public let keyLength: Int?           // Key length in bits
    public let algorithm: String?        // Key algorithm
    public let keyId: String             // Key ID
    public let creationDate: String?     // Creation date
    public let expirationDate: String?   // Expiration date
    public let userId: String?           // User ID
    public let fingerprint: String?      // Key fingerprint
    public let capabilities: String?     // Key capabilities (S, C, E, A)
    
    // Computed properties
    public var isExpired: Bool           // Whether key is expired
    public var isPrimaryKey: Bool        // Whether this is a primary key
    public var canSign: Bool             // Whether key can sign
    public var canEncrypt: Bool          // Whether key can encrypt
    public var canCertify: Bool          // Whether key can certify
}
```

### ImportResult

Handles key import operations.

```swift
public final class ImportResult: BaseStatusHandler {
    public var count = 0              // Total keys processed
    public var noUserId = 0           // Keys without user ID
    public var imported = 0           // Successfully imported
    public var importedRsa = 0        // RSA keys imported
    public var unchanged = 0          // Unchanged keys
    public var nUids = 0             // New user IDs
    public var nSubk = 0             // New subkeys
    public var nSigs = 0             // New signatures
    public var nRevoc = 0            // New revocations
    public var secRead = 0           // Secret keys read
    public var secImported = 0       // Secret keys imported
    public var secDups = 0           // Duplicate secret keys
    public var notImported = 0       // Failed imports
    
    public var results: [[String: Any]] = []  // Detailed results
    public var fingerprints: [String] = []    // Imported fingerprints
    public var status: String?                // Import status
    
    public var isSuccessful: Bool             // Whether import succeeded
    public func summary() -> String           // Summary of results
}
```

## Core Types

### GPGVersion

Represents a GPG version.

```swift
public struct GPGVersion: Sendable {
    public let major: Int       // Major version
    public let minor: Int       // Minor version
    public let patch: Int?      // Patch version (optional)
    
    public init(major: Int, minor: Int, patch: Int? = nil)
    static func parse(from data: Data) -> GPGVersion? // Parse from GPG output
}

extension GPGVersion: Comparable // Supports version comparison
```

## Error Types

### GPGError

Comprehensive error enumeration with detailed context and recovery suggestions.

```swift
public enum GPGError: LocalizedError, Equatable {
    // Initialization Errors
    case gpgNotAvailable(String)
    case invalidHomeDirecory(String)
    case unsupportedGPGVersion(GPGVersion, minimum: GPGVersion)
    case configurationError(String)
    
    // Input/Output Errors
    case invalidInput(String)
    case invalidPassphrase(String)
    case fileNotFound(String)
    case fileAccessDenied(String)
    case permissionDenied(String)
    case diskFull
    case diskReadError(String)
    
    // Process Errors
    case processLaunchFailed(String)
    case processTerminated(Int32, stderr: String)
    case processTimeout(timeoutSeconds: Double)
    case processInterrupted
    
    // Key Management Errors
    case keyNotFound(String)
    case keyAlreadyExists(String)
    case keyExpired(String)
    case keyRevoked(String)
    case keyUntrusted(String)
    case invalidKeyData(String)
    case keyGenerationFailed(String)
    
    // Cryptographic Operation Errors
    case signatureFailed(String)
    case verificationFailed(String)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case noValidRecipients([String])
    case badSignature(String)
    case expiredSignature(String)
    case noSecretKey(String)
    case noPublicKey(String)
    
    // Network/Communication Errors
    case keyserverError(String)
    case networkTimeout
    case networkUnavailable
    
    // Generic Errors
    case unknownError(String)
    case internalError(String)
    
    // Properties
    public var errorDescription: String?    // Detailed error description
    public var failureReason: String?       // User-friendly failure reason
    public var recoverySuggestion: String?  // Recovery suggestions
}
```

## Logging

### GPGLogger

Comprehensive logging system with multiple backends.

```swift
public final class GPGLogger: @unchecked Sendable {
    public static let shared: GPGLogger    // Shared logger instance
    
    public var level: GPGLogLevel         // Current log level
    public var isEnabled: Bool            // Whether logging is enabled
    
    // Configuration
    public func addHandler(_ handler: GPGLogHandler)
    public func removeAllHandlers()
    public func setConsoleLogging(enabled: Bool)
    @available(macOS 11.0, *)
    public func setOSLogging(enabled: Bool, subsystem: String, category: String)
    
    // Logging methods
    public func debug(_ message: String, category: String = "GPG")
    public func info(_ message: String, category: String = "GPG")
    public func warning(_ message: String, category: String = "GPG")
    public func error(_ message: String, category: String = "GPG")
    public func critical(_ message: String, category: String = "GPG")
    
    // Convenience methods
    public func logCommand(_ command: [String], category: String = "Command")
    public func logProcessResult(exitCode: Int32, stderr: String, category: String = "Process")
    public func logStatusMessage(key: String, value: String, category: String = "Status")
    
    // Operation timing
    public func logOperation<T>(_ operation: String, block: () throws -> T) rethrows -> T
    public func logOperationAsync<T>(_ operation: String, block: () async throws -> T) async rethrows -> T
}
```

### GPGLogLevel

Log level enumeration.

```swift
public enum GPGLogLevel: Int, CaseIterable, Comparable, Sendable {
    case debug = 0      // Detailed debugging information
    case info = 1       // General information
    case warning = 2    // Warning messages
    case error = 3      // Error messages
    case critical = 4   // Critical errors
    
    public var description: String  // String representation
    public var emoji: String        // Emoji representation
}
```

### GPGLogHandler Protocol

Protocol for custom log handlers.

```swift
public protocol GPGLogHandler {
    func log(
        level: GPGLogLevel,
        message: String,
        category: String,
        file: String,
        function: String,
        line: Int
    )
}
```

Built-in handlers:
- `GPGConsoleLogHandler`: Logs to console with timestamps
- `GPGOSLogHandler`: Logs to Apple's unified logging system (macOS 11.0+)

## Utility Functions

### GPGUtilities

Utility functions for GPG operations.

```swift
public enum GPGUtilities {
    // Shell quoting
    public static func shellQuote(_ string: String) -> String
    public static func noQuote(_ string: String) -> String
    
    // Validation
    public static func isValidPassphrase(_ passphrase: String) -> Bool
    
    // Stream creation
    public static func makeMemoryStream(from data: Data) -> InputStream
    public static func makeBinaryStream(from string: String, encoding: String.Encoding) -> InputStream?
    
    // Type checking
    public static func isSequence<T>(_ object: T) -> Bool
}
```

## Usage Patterns

### Error Handling Pattern

```swift
do {
    let gpg = try GnuPG()
    let result = await gpg.someOperation()
    
    guard result.isSuccessful else {
        print("Operation failed: \(result.status ?? "unknown")")
        return
    }
    
    // Process successful result
} catch let error as GPGError {
    print("GPG Error: \(error.errorDescription ?? "Unknown")")
    print("Suggestion: \(error.recoverySuggestion ?? "None")")
} catch {
    print("Unexpected error: \(error)")
}
```

### Logging Pattern

```swift
// Configure logging once
GPGLogger.shared.level = .info
GPGLogger.shared.setConsoleLogging(enabled: true)

// Use operation logging for timing
let result = await GPGLogger.shared.logOperationAsync("Key Generation") {
    return await gpg.generateKey(...)
}
```

### Concurrent Operations Pattern

```swift
// Run operations concurrently
async let signTask = gpg.sign(message: "message1")
async let encryptTask = gpg.encrypt(message: "message2", recipients: ["user@example.com"])

let signResult = await signTask
let encryptResult = await encryptTask

// Process results...
```

This completes the comprehensive API reference for the Swift GnuPG library.

## See Also

- <doc:GettingStarted>
- <doc:GPGInstallation> 
- <doc:Examples>
- <doc:Troubleshooting>
- ``GnuPG``
- ``GPGError``
- ``GPGLogger``

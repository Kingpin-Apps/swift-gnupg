# Swift GnuPG

A comprehensive Swift wrapper for GnuPG operations, providing a modern, async/await interface for cryptographic operations including signing, verification, encryption, decryption, and key management.

This is a Swift port of [python-gnupg](https://gnupg.readthedocs.io/), maintaining API compatibility while embracing Swift's concurrency model and type safety.

[![Swift 6.0](https://img.shields.io/badge/Swift-6.0-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)](https://swift.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **⚠️ Important Prerequisite:** This library requires [GnuPG 2.0+](https://gnupg.org/) to be installed on your system. Swift GnuPG acts as a wrapper around the `gpg` command-line tool and cannot function without it.

## Features

✅ **Complete GPG Operations Suite**
- Digital signature creation and verification
- Public key and symmetric encryption/decryption  
- Comprehensive key management (list, import, export, generate, delete)
- Support for all GPG options (ASCII armor, detached signatures, etc.)

✅ **Modern Swift Design**
- Full async/await support with proper concurrency
- Strong typing with comprehensive error handling
- Sendable compliance for safe concurrent usage
- Swift Testing framework integration

✅ **Robust Implementation**
- Automatic GPG binary discovery across platforms
- Comprehensive logging with multiple backends (Console, OSLog)
- Detailed status message parsing
- Memory-safe process management

✅ **Production Ready**
- Extensive test coverage with real GPG integration
- Comprehensive error types with recovery suggestions
- Performance optimized with configurable options
- Python-gnupg API compatibility

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-gnupg.git", from: "0.1.0")
]
```

### Requirements

- **Swift 6.0+**
- **GnuPG 2.0+** installed on the system
- **macOS 10.15+** or **Linux**

#### Installing GnuPG

**macOS:**
```bash
brew install gnupg
```

**Ubuntu/Debian:**
```bash
sudo apt install gnupg
```

**RHEL/CentOS:**
```bash
sudo yum install gnupg2
```

## Quick Start

### Basic Usage

```swift
import GnuPG

// Initialize GPG (automatically finds GPG binary)
let gpg = try GnuPG()

// List available keys
let keys = await gpg.listKeys()
print("Found \(keys.keys.count) public keys")

// Sign a message
let signResult = await gpg.sign(message: "Hello, World!")
if signResult.isSuccessful {
    print("Message signed successfully!")
}

// Encrypt for a recipient
let encryptResult = await gpg.encrypt(
    message: "Secret message", 
    recipients: ["user@example.com"]
)

// Verify a signature
let verifyResult = await gpg.verify(message: signedMessage)
print("Signature valid: \(verifyResult.valid)")
```

### Advanced Configuration

```swift
// Custom GPG configuration
let customGPG = try GnuPG(
    gpgBinary: "/usr/local/bin/gpg",
    gnupgHome: "/path/to/gpg/home",
    verbose: true,
    options: ["--cipher-algo", "AES256", "--digest-algo", "SHA512"]
)

// Enable detailed logging
customGPG.logger.level = .debug
customGPG.logger.setConsoleLogging(enabled: true)

// macOS: Enable OSLog integration
if #available(macOS 11.0, *) {
    customGPG.logger.setOSLogging(enabled: true, subsystem: "com.myapp.crypto")
}
```

## Core Operations

### Digital Signatures

```swift
// Sign with default key
let signResult = await gpg.sign(message: "Document to sign")

// Sign with specific key and options
let advancedSign = await gpg.sign(
    message: "Important document",
    keyId: "user@example.com",
    passphrase: "secret",
    clearsign: true,
    detach: false,
    armor: true
)

// Sign a file
let fileSignResult = await gpg.signFile(
    filePath: "/path/to/document.txt",
    outputPath: "/path/to/document.txt.sig",
    detach: true
)
```

### Signature Verification

```swift
// Verify inline signature
let verifyResult = await gpg.verify(message: signedMessage)
if verifyResult.valid {
    print("Signature by: \(verifyResult.username ?? "unknown")")
    print("Key ID: \(verifyResult.keyId ?? "unknown")")
    print("Fingerprint: \(verifyResult.fingerprint ?? "unknown")")
}

// Verify detached signature
let detachedVerify = await gpg.verifyFile(
    filePath: "/path/to/document.txt",
    signaturePath: "/path/to/document.txt.sig"
)

// Check signature details
for (sigId, info) in verifyResult.sigInfo {
    print("Signature \(sigId): \(info)")
}
```

### Encryption & Decryption

```swift
// Public key encryption
let encryptResult = await gpg.encrypt(
    message: "Top secret message",
    recipients: ["alice@example.com", "bob@example.com"],
    armor: true,
    sign: true // Also sign the message
)

// Symmetric encryption
let symmetricResult = await gpg.encryptSymmetric(
    message: "Secret data",
    passphrase: "strong-password"
)

// Decrypt message
let decryptResult = await gpg.decrypt(
    message: encryptedMessage,
    passphrase: "secret"
)

if decryptResult.isSuccessful {
    let plaintext = String(data: decryptResult.data!, encoding: .utf8)
    print("Decrypted: \(plaintext ?? "Unable to decode")")
    
    // Check if decryption also verified a signature
    if decryptResult.signatureValid {
        print("Signature verified by: \(decryptResult.signatureUser ?? "unknown")")
    }
}
```

### Key Management

```swift
// List all keys
let publicKeys = await gpg.listKeys()
let secretKeys = await gpg.listKeys(secretKeys: true)

// Find specific keys
if let key = publicKeys.findKey(byId: "alice@example.com") {
    print("Key: \(key.keyId)")
    print("User: \(key.userId ?? "No user ID")")
    print("Capabilities: \(key.capabilities ?? "None")")
    print("Expires: \(key.isExpired ? "Yes" : "No")")
}

// Import keys
let keyData = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----
"""

let importResult = await gpg.importKeys(keyString: keyData)
print("Imported \(importResult.imported) keys")

// Export keys
if let exportedData = await gpg.exportKeys(keyId: "alice@example.com") {
    let exportedString = String(data: exportedData, encoding: .utf8)!
    print("Exported key:\n\(exportedString)")
}

// Generate new key pair
let generateResult = await gpg.generateKey(
    keyType: "RSA",
    keySize: 3072,
    userId: "New User <newuser@example.com>",
    passphrase: "strong-passphrase"
)

// Delete keys
let deleted = await gpg.deleteKey(keyId: "old-key@example.com")
```

## Error Handling

The library provides comprehensive error handling with detailed context and recovery suggestions:

```swift
do {
    let gpg = try GnuPG()
    let result = await gpg.sign(message: "test")
    
    if !result.isSuccessful {
        print("Signing failed: \(result.status ?? "unknown error")")
    }
} catch let error as GPGError {
    print("Error: \(error.errorDescription ?? "Unknown error")")
    print("Reason: \(error.failureReason ?? "No specific reason")")
    print("Suggestion: \(error.recoverySuggestion ?? "No suggestion available")")
    
    switch error {
    case .gpgNotAvailable(let binary):
        print("Install GPG or check PATH. Missing binary: \(binary)")
    case .invalidPassphrase(let reason):
        print("Passphrase issue: \(reason)")
    case .keyNotFound(let keyId):
        print("Key not found: \(keyId)")
    case .processTerminated(let code, let stderr):
        print("GPG process failed with code \(code): \(stderr)")
    default:
        print("Other error: \(error)")
    }
}
```

## Logging

Comprehensive logging is available with multiple backends:

```swift
import GnuPG

// Configure logging level
GPGLogger.shared.level = .debug  // .debug, .info, .warning, .error, .critical

// Enable console logging
GPGLogger.shared.setConsoleLogging(enabled: true)

// Enable OSLog (macOS 11.0+)
if #available(macOS 11.0, *) {
    GPGLogger.shared.setOSLogging(enabled: true, subsystem: "com.myapp.crypto")
}

// Use operation logging for timing
let result = await GPGLogger.shared.logOperationAsync("Key Generation") {
    return await gpg.generateKey(
        keyType: "RSA",
        keySize: 2048, 
        userId: "test@example.com",
        passphrase: "test123"
    )
}
```

### Custom Log Handlers

```swift
struct FileLogHandler: GPGLogHandler {
    private let fileHandle: FileHandle
    
    init(logPath: String) throws {
        self.fileHandle = try FileHandle(forWritingTo: URL(fileURLWithPath: logPath))
    }
    
    func log(level: GPGLogLevel, message: String, category: String, file: String, function: String, line: Int) {
        let logEntry = "[\(level.description)] \(category): \(message)\n"
        fileHandle.write(logEntry.data(using: .utf8)!)
    }
}

// Add custom handler
let fileHandler = try FileLogHandler(logPath: "/tmp/gpg.log")
GPGLogger.shared.addHandler(fileHandler)
```

## Testing

The library includes comprehensive tests using Swift Testing:

```swift
// Run all tests
swift test

// Run specific test suites
swift test --filter "Integration"
swift test --filter "KeyOperations"
swift test --filter "Basic"

// Test with verbose output
swift test --filter "testGPGBinaryDiscoveryAndVersion"
```

### Test Organization

- **BasicGnuPGTests**: Core functionality without GPG binary
- **KeyOperationsTests**: Key management operations  
- **SignOperationsTests**: Digital signature operations
- **VerifyOperationsTests**: Signature verification
- **EncryptDecryptTests**: Encryption and decryption
- **IntegrationTests**: End-to-end workflows with real GPG

## Architecture

```
Sources/GnuPG/
├── GnuPG.swift                 # Main class with process management
├── Core/
│   ├── GPGTypes.swift         # Version, errors, and type definitions
│   ├── GPGLogger.swift        # Comprehensive logging system
│   └── StatusHandler.swift    # GPG status message processing
├── Results/                   # Result classes for each operation
│   ├── SignResult.swift
│   ├── VerifyResult.swift
│   ├── EncryptResult.swift
│   ├── DecryptResult.swift
│   ├── ListKeysResult.swift   # Includes GPGKey struct
│   └── ImportResult.swift
├── Operations/               # Operation implementations
│   ├── SignOperations.swift
│   ├── VerifyOperations.swift
│   ├── EncryptOperations.swift
│   ├── DecryptOperations.swift
│   └── KeyOperations.swift
└── Utilities/
    └── GPGUtilities.swift    # Helper functions and validation
```

## Performance Considerations

- **Process Reuse**: Each operation creates a new GPG process for security and reliability
- **Memory Management**: Proper cleanup of file handles and process resources
- **Streaming**: Large file operations use streaming to minimize memory usage
- **Concurrency**: All operations are async and can be run concurrently
- **Buffering**: Configurable buffer sizes for optimal performance

```swift
// Configure for large files
gpg.bufferSize = 65536  // 64KB buffer for large operations

// Concurrent operations
async let signTask = gpg.sign(message: "message1")
async let encryptTask = gpg.encrypt(message: "message2", recipients: ["user@example.com"])

let signResult = await signTask
let encryptResult = await encryptTask
```

## Troubleshooting

### Common Issues

**GPG Not Found:**
```
Error: GPG binary not available: gpg. Please install GPG or specify the correct path.
```
Solution: Install GPG or specify the full path:
```swift
let gpg = try GnuPG(gpgBinary: "/usr/local/bin/gpg")
```

**Permission Denied:**
```
Error: Permission denied for operation: signing
```
Solution: Check GPG home directory permissions and key access.

**Key Not Found:**
```  
Error: Key not found: user@example.com
```
Solution: Import the key first or check the key identifier.

**Passphrase Issues:**
```
Error: Invalid passphrase: contains newline or null characters
```
Solution: Ensure passphrase doesn't contain special characters.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests
4. Run the test suite (`swift test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/your-org/swift-gnupg.git
cd swift-gnupg

# Install dependencies
brew install gnupg

# Run tests
swift test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Based on [python-gnupg](https://gnupg.readthedocs.io/) by Vinay Sajip
- Inspired by the need for a modern Swift cryptography interface
- Built with Swift's modern concurrency features

## Changelog

### 1.0.0 (2024-XX-XX)
- Initial release with complete GPG operations
- Full async/await support
- Comprehensive error handling and logging
- Production-ready with extensive test coverage

---

For more detailed examples and API documentation, see the [Documentation](docs/) directory.

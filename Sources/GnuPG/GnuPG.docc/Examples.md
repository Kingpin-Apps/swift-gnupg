# Swift GnuPG Examples

@Metadata {
   @PageKind(article)
   @PageColor(blue)
   @Available(macOS, introduced: "10.15")
}

Practical examples demonstrating common use cases for the Swift GnuPG library.

## Prerequisites

> Important: All examples in this guide assume you have:
> - **GnuPG 2.0+** installed and working (see <doc:GPGInstallation>)
> - **Swift GnuPG library** added to your project (see <doc:GettingStarted>)
> - **At least one GPG key** in your keyring for testing

If you encounter issues, check the <doc:Troubleshooting> guide.

## Overview

This document provides practical examples demonstrating common use cases for the Swift GnuPG library.

## Table of Contents

- [Basic Setup](#basic-setup)
- [Digital Signatures](#digital-signatures)
- [Encryption & Decryption](#encryption--decryption)
- [Key Management](#key-management)
- [Advanced Usage](#advanced-usage)
- [Error Handling](#error-handling)
- [Real-World Scenarios](#real-world-scenarios)

## Basic Setup

### Simple Initialization

```swift
import GnuPG

// Basic initialization (automatically finds GPG)
let gpg = try GnuPG()

// Check GPG version
if let version = gpg.version {
    print("Using GPG version \(version.major).\(version.minor)")
}
```

### Custom Configuration

```swift
// Advanced configuration
let customGPG = try GnuPG(
    gpgBinary: "/usr/local/bin/gpg",
    gnupgHome: "~/.gnupg-custom",
    verbose: true,
    options: ["--cipher-algo", "AES256", "--digest-algo", "SHA512"]
)

// Enable detailed logging
customGPG.logger.level = .debug
customGPG.logger.setConsoleLogging(enabled: true)
```

## Digital Signatures

### Basic Message Signing

```swift
func signMessage() async {
    do {
        let gpg = try GnuPG()
        
        let message = "This document is authentic and has not been tampered with."
        let signResult = await gpg.sign(message: message)
        
        if signResult.isSuccessful {
            if let signedData = signResult.data,
               let signedMessage = String(data: signedData, encoding: .utf8) {
                print("Signed message:")
                print(signedMessage)
                
                print("Signature details:")
                print("- Key ID: \(signResult.keyId ?? "unknown")")
                print("- Fingerprint: \(signResult.fingerprint ?? "unknown")")
                print("- Hash Algorithm: \(signResult.hashAlgo ?? "unknown")")
            }
        } else {
            print("Signing failed: \(signResult.status ?? "unknown error")")
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### Detached Signature

```swift
func createDetachedSignature() async {
    do {
        let gpg = try GnuPG()
        
        let document = "Important contract terms and conditions..."
        
        // Create detached signature
        let signResult = await gpg.sign(
            message: document,
            keyId: "signing-key@company.com",
            passphrase: "secure-passphrase",
            detach: true,
            armor: true
        )
        
        if signResult.isSuccessful {
            // Save original document
            try document.write(to: URL(fileURLWithPath: "contract.txt"), 
                              atomically: true, encoding: .utf8)
            
            // Save detached signature
            if let signatureData = signResult.data {
                try signatureData.write(to: URL(fileURLWithPath: "contract.txt.sig"))
                print("Created detached signature: contract.txt.sig")
            }
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### File Signing

```swift
func signFile() async {
    do {
        let gpg = try GnuPG()
        
        let signResult = await gpg.signFile(
            filePath: "/path/to/document.pdf",
            keyId: "user@example.com",
            detach: true,
            outputPath: "/path/to/document.pdf.sig"
        )
        
        if signResult.isSuccessful {
            print("File signed successfully")
            print("Signature saved to: document.pdf.sig")
        }
    } catch {
        print("Error signing file: \(error)")
    }
}
```

### Signature Verification

```swift
func verifySignature() async {
    do {
        let gpg = try GnuPG()
        
        // Verify inline signature
        let signedMessage = """
        -----BEGIN PGP SIGNED MESSAGE-----
        Hash: SHA256
        
        This is the original message content.
        -----BEGIN PGP SIGNATURE-----
        ...signature data...
        -----END PGP SIGNATURE-----
        """
        
        let verifyResult = await gpg.verify(message: signedMessage)
        
        print("Signature verification:")
        print("- Valid: \(verifyResult.valid)")
        print("- Signer: \(verifyResult.username ?? "unknown")")
        print("- Key ID: \(verifyResult.keyId ?? "unknown")")
        print("- Fingerprint: \(verifyResult.fingerprint ?? "unknown")")
        print("- Trust level: \(verifyResult.trustLevel ?? -1)")
        
        if !verifyResult.problems.isEmpty {
            print("- Problems found:")
            for problem in verifyResult.problems {
                print("  - \(problem)")
            }
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### Verify Detached Signature

```swift
func verifyDetachedSignature() async {
    do {
        let gpg = try GnuPG()
        
        let verifyResult = await gpg.verifyFile(
            filePath: "/path/to/document.txt",
            signaturePath: "/path/to/document.txt.sig"
        )
        
        if verifyResult.valid {
            print("✅ Signature is valid")
            print("Signed by: \(verifyResult.username ?? "unknown")")
            print("Trust level: \(verifyResult.trustText ?? "unknown")")
        } else {
            print("❌ Signature verification failed")
            if let status = verifyResult.status {
                print("Reason: \(status)")
            }
        }
    } catch {
        print("Error: \(error)")
    }
}
```

## Encryption & Decryption

### Basic Encryption

```swift
func encryptMessage() async {
    do {
        let gpg = try GnuPG()
        
        let secretMessage = "This is confidential information."
        let recipients = ["alice@company.com", "bob@company.com"]
        
        let encryptResult = await gpg.encrypt(
            message: secretMessage,
            recipients: recipients,
            armor: true
        )
        
        if encryptResult.isSuccessful {
            if let encryptedData = encryptResult.data,
               let encryptedMessage = String(data: encryptedData, encoding: .utf8) {
                print("Encrypted message:")
                print(encryptedMessage)
                
                print("Encryption summary: \(encryptResult.summary())")
            }
        } else {
            print("Encryption failed: \(encryptResult.status ?? "unknown error")")
            
            if !encryptResult.invalidRecipients.isEmpty {
                print("Invalid recipients: \(encryptResult.invalidRecipients)")
            }
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### Encrypt and Sign

```swift
func encryptAndSign() async {
    do {
        let gpg = try GnuPG()
        
        let message = "Confidential and authenticated message."
        
        let encryptResult = await gpg.encrypt(
            message: message,
            recipients: ["recipient@example.com"],
            sign: true,
            keyId: "sender@example.com",
            passphrase: "signing-passphrase",
            armor: true
        )
        
        if encryptResult.isSuccessful {
            print("Message encrypted and signed successfully!")
            print("Recipients: \(encryptResult.recipients)")
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### Symmetric Encryption

```swift
func symmetricEncryption() async {
    do {
        let gpg = try GnuPG()
        
        let message = "Secret data encrypted with passphrase."
        let passphrase = "strong-encryption-key"
        
        let encryptResult = await gpg.encryptSymmetric(
            message: message,
            passphrase: passphrase,
            armor: true
        )
        
        if encryptResult.isSuccessful {
            print("Symmetric encryption successful")
            
            // Store encrypted data
            if let encryptedData = encryptResult.data {
                try encryptedData.write(to: URL(fileURLWithPath: "encrypted_data.asc"))
            }
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### Decryption

```swift
func decryptMessage() async {
    do {
        let gpg = try GnuPG()
        
        let encryptedMessage = try String(contentsOf: URL(fileURLWithPath: "encrypted_data.asc"))
        
        let decryptResult = await gpg.decrypt(
            message: encryptedMessage,
            passphrase: "decryption-passphrase"
        )
        
        if decryptResult.isSuccessful {
            if let decryptedData = decryptResult.data,
               let plaintext = String(data: decryptedData, encoding: .utf8) {
                print("Decrypted message: \(plaintext)")
                
                print("Decryption details:")
                print("- Key ID: \(decryptResult.keyId ?? "unknown")")
                print("- Fingerprint: \(decryptResult.fingerprint ?? "unknown")")
                
                // Check if message was also signed
                if decryptResult.signatureValid {
                    print("- Signature verified by: \(decryptResult.signatureUser ?? "unknown")")
                    print("- Signature key: \(decryptResult.signatureKeyId ?? "unknown")")
                }
                
                print("Summary: \(decryptResult.summary())")
            }
        } else {
            print("Decryption failed: \(decryptResult.status ?? "unknown error")")
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### File Encryption

```swift
func encryptFile() async {
    do {
        let gpg = try GnuPG()
        
        let encryptResult = await gpg.encryptFile(
            filePath: "/path/to/sensitive_data.txt",
            recipients: ["backup@company.com"],
            armor: true,
            outputPath: "/path/to/sensitive_data.txt.asc"
        )
        
        if encryptResult.isSuccessful {
            print("File encrypted successfully")
            print("Output: sensitive_data.txt.asc")
        }
    } catch {
        print("Error: \(error)")
    }
}
```

## Key Management

### List All Keys

```swift
func listKeys() async {
    do {
        let gpg = try GnuPG()
        
        // List public keys
        let publicKeys = await gpg.listKeys()
        print("Public Keys (\(publicKeys.keys.count) found):")
        for key in publicKeys.keys {
            print("- \(key.keyId): \(key.userId ?? "No user ID")")
            print("  Type: \(key.type), Length: \(key.keyLength ?? 0) bits")
            print("  Capabilities: \(key.capabilities ?? "None")")
            print("  Expires: \(key.isExpired ? "Yes" : "No")")
            print()
        }
        
        // List secret keys
        let secretKeys = await gpg.listKeys(secretKeys: true)
        print("Secret Keys (\(secretKeys.keys.count) found):")
        for key in secretKeys.keys {
            print("- \(key.keyId): \(key.userId ?? "No user ID")")
            print("  Can sign: \(key.canSign)")
            print("  Can certify: \(key.canCertify)")
            print()
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### Import Public Key

```swift
func importPublicKey() async {
    do {
        let gpg = try GnuPG()
        
        let publicKeyData = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        
        mQENBF2...  (key data here)
        ...
        -----END PGP PUBLIC KEY BLOCK-----
        """
        
        let importResult = await gpg.importKeys(keyString: publicKeyData)
        
        print("Import Results:")
        print("- Keys processed: \(importResult.count)")
        print("- Keys imported: \(importResult.imported)")
        print("- Keys unchanged: \(importResult.unchanged)")
        print("- Keys not imported: \(importResult.notImported)")
        
        if importResult.isSuccessful {
            print("✅ Key import successful")
            print("Summary: \(importResult.summary())")
            
            if !importResult.fingerprints.isEmpty {
                print("Imported fingerprints:")
                for fingerprint in importResult.fingerprints {
                    print("- \(fingerprint)")
                }
            }
        } else {
            print("❌ Key import failed: \(importResult.status ?? "unknown error")")
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### Export Keys

```swift
func exportKeys() async {
    do {
        let gpg = try GnuPG()
        
        // Export specific public key
        if let publicKeyData = await gpg.exportKeys(keyId: "alice@company.com") {
            let keyString = String(data: publicKeyData, encoding: .utf8)!
            print("Exported public key:")
            print(keyString)
            
            // Save to file
            try publicKeyData.write(to: URL(fileURLWithPath: "alice_public_key.asc"))
        }
        
        // Export all public keys
        if let allKeysData = await gpg.exportKeys() {
            try allKeysData.write(to: URL(fileURLWithPath: "all_public_keys.asc"))
            print("Exported all public keys to: all_public_keys.asc")
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### Generate Key Pair

```swift
func generateKeyPair() async {
    do {
        let gpg = try GnuPG()
        
        print("Generating new key pair...")
        
        let generateResult = await gpg.generateKey(
            keyType: "RSA",
            keySize: 3072,
            userId: "New User <newuser@example.com>",
            passphrase: "strong-passphrase-for-new-key",
            expires: "2y"  // Expires in 2 years
        )
        
        if generateResult.isSuccessful {
            print("✅ Key generation successful")
            print("Generated \(generateResult.imported) key(s)")
            
            if !generateResult.fingerprints.isEmpty {
                print("New key fingerprints:")
                for fingerprint in generateResult.fingerprints {
                    print("- \(fingerprint)")
                }
            }
        } else {
            print("❌ Key generation failed: \(generateResult.status ?? "unknown error")")
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### Find and Delete Keys

```swift
func manageKeys() async {
    do {
        let gpg = try GnuPG()
        
        // Find a specific key
        if let foundKey = await gpg.findKey(byIdentifier: "test@example.com") {
            print("Found key:")
            print("- ID: \(foundKey.keyId)")
            print("- User: \(foundKey.userId ?? "No user ID")")
            print("- Type: \(foundKey.type)")
            print("- Expired: \(foundKey.isExpired)")
            
            // Check key capabilities
            if foundKey.canSign {
                print("- Can sign documents")
            }
            if foundKey.canEncrypt {
                print("- Can encrypt messages")
            }
            
            // Delete the key if it's expired
            if foundKey.isExpired {
                let deleted = await gpg.deleteKey(keyId: foundKey.keyId)
                if deleted {
                    print("✅ Expired key deleted successfully")
                } else {
                    print("❌ Failed to delete expired key")
                }
            }
        } else {
            print("Key not found")
        }
    } catch {
        print("Error: \(error)")
    }
}
```

## Advanced Usage

### Concurrent Operations

```swift
func concurrentOperations() async {
    do {
        let gpg = try GnuPG()
        
        // Run multiple operations concurrently
        async let signTask = gpg.sign(message: "Document 1")
        async let encryptTask = gpg.encrypt(message: "Document 2", recipients: ["user@example.com"])
        async let listKeysTask = gpg.listKeys()
        
        // Wait for all operations to complete
        let signResult = await signTask
        let encryptResult = await encryptTask
        let keysResult = await listKeysTask
        
        // Process results
        print("Sign result: \(signResult.isSuccessful ? "✅" : "❌")")
        print("Encrypt result: \(encryptResult.isSuccessful ? "✅" : "❌")")
        print("Found \(keysResult.keys.count) keys")
        
    } catch {
        print("Error: \(error)")
    }
}
```

### Custom Logging

```swift
func customLogging() async {
    // Custom file log handler
    struct FileLogHandler: GPGLogHandler {
        private let fileURL: URL
        
        init(logPath: String) {
            self.fileURL = URL(fileURLWithPath: logPath)
        }
        
        func log(level: GPGLogLevel, message: String, category: String, file: String, function: String, line: Int) {
            let timestamp = ISO8601DateFormatter().string(from: Date())
            let logEntry = "[\(timestamp)] [\(level.description)] \(category): \(message)\n"
            
            if let data = logEntry.data(using: .utf8) {
                try? data.append(to: fileURL)
            }
        }
    }
    
    // Configure logging
    let logger = GPGLogger.shared
    logger.level = .debug
    logger.removeAllHandlers()
    
    // Add custom file handler
    let fileHandler = FileLogHandler(logPath: "/tmp/gpg_operations.log")
    logger.addHandler(fileHandler)
    logger.addHandler(GPGConsoleLogHandler())
    
    do {
        let gpg = try GnuPG()
        gpg.logger = logger
        
        // Operations will now be logged to both console and file
        // logOperationAsync wraps the operation with timing and error logging
        let result = await logger.logOperationAsync("Key Listing") {
            return await gpg.listKeys()
        }
        
        print("Operation completed, check /tmp/gpg_operations.log for details")
    } catch {
        print("Error: \(error)")
    }
}

extension Data {
    func append(to url: URL) throws {
        if FileManager.default.fileExists(atPath: url.path) {
            let fileHandle = try FileHandle(forWritingTo: url)
            fileHandle.seekToEndOfFile()
            fileHandle.write(self)
            fileHandle.closeFile()
        } else {
            try write(to: url)
        }
    }
}
```

### Batch Operations

```swift
func batchOperations() async {
    do {
        let gpg = try GnuPG()
        
        let documents = [
            "Document 1: Important contract",
            "Document 2: Financial report", 
            "Document 3: Technical specifications"
        ]
        
        let recipients = ["alice@company.com", "bob@company.com"]
        
        // Process all documents
        var results: [(document: String, encrypted: Bool, signed: Bool)] = []
        
        for (index, document) in documents.enumerated() {
            print("Processing document \(index + 1)...")
            
            // Encrypt and sign each document
            async let encryptTask = gpg.encrypt(
                message: document,
                recipients: recipients,
                sign: true,
                keyId: "company@company.com",
                armor: true
            )
            
            let encryptResult = await encryptTask
            
            let success = encryptResult.isSuccessful
            results.append((document: document, encrypted: success, signed: success))
            
            if success {
                // Save encrypted document
                if let encryptedData = encryptResult.data {
                    let filename = "document_\(index + 1)_encrypted.asc"
                    try encryptedData.write(to: URL(fileURLWithPath: filename))
                    print("✅ Saved \(filename)")
                }
            } else {
                print("❌ Failed to process document \(index + 1)")
            }
        }
        
        // Summary
        print("\nBatch Operation Summary:")
        let successCount = results.filter { $0.encrypted && $0.signed }.count
        print("Processed: \(results.count) documents")
        print("Successful: \(successCount) documents")
        print("Failed: \(results.count - successCount) documents")
        
    } catch {
        print("Error: \(error)")
    }
}
```

## Error Handling

### Comprehensive Error Handling

```swift
func handleAllErrors() async {
    do {
        let gpg = try GnuPG()
        let result = await gpg.sign(message: "test message")
        
        if result.isSuccessful {
            print("✅ Operation successful")
        } else {
            print("❌ Operation failed: \(result.status ?? "unknown")")
        }
        
    } catch let error as GPGError {
        handleGPGError(error)
    } catch {
        print("❌ Unexpected error: \(error)")
    }
}

func handleGPGError(_ error: GPGError) {
    print("🔴 GPG Error Occurred")
    print("Description: \(error.errorDescription ?? "Unknown error")")
    print("Reason: \(error.failureReason ?? "No specific reason")")
    print("Suggestion: \(error.recoverySuggestion ?? "No suggestion available")")
    
    switch error {
    case .gpgNotAvailable(let binary):
        print("📋 Action needed: Install GPG or check PATH")
        print("Missing binary: \(binary)")
        
    case .invalidPassphrase(let reason):
        print("📋 Action needed: Check passphrase")
        print("Issue: \(reason)")
        
    case .keyNotFound(let keyId):
        print("📋 Action needed: Import the required key")
        print("Key ID: \(keyId)")
        
    case .processTerminated(let code, let stderr):
        print("📋 GPG process failed with exit code: \(code)")
        print("Error output: \(stderr)")
        
    case .fileNotFound(let path):
        print("📋 Action needed: Check file path")
        print("Path: \(path)")
        
    case .noValidRecipients(let recipients):
        print("📋 Action needed: Import recipient keys")
        print("Recipients: \(recipients.joined(separator: ", "))")
        
    default:
        print("📋 Other GPG error occurred")
    }
}
```

## Real-World Scenarios

### Secure Document Workflow

```swift
class SecureDocumentManager {
    private let gpg: GnuPG
    private let companyKeyId = "company@example.com"
    
    init() throws {
        self.gpg = try GnuPG()
        
        // Configure logging for audit trail
        gpg.logger.level = .info
        gpg.logger.setConsoleLogging(enabled: true)
    }
    
    func secureDocument(_ content: String, for recipients: [String]) async -> String? {
        do {
            // Sign and encrypt the document
            let result = await gpg.encrypt(
                message: content,
                recipients: recipients,
                sign: true,
                keyId: companyKeyId,
                armor: true
            )
            
            if result.isSuccessful {
                return String(data: result.data!, encoding: .utf8)
            } else {
                print("❌ Document security failed: \(result.status ?? "unknown")")
                return nil
            }
        } catch {
            print("❌ Error securing document: \(error)")
            return nil
        }
    }
    
    func verifyAndDecrypt(_ securedContent: String) async -> (content: String?, isVerified: Bool) {
        do {
            let decryptResult = await gpg.decryptAndVerify(message: securedContent)
            
            if decryptResult.isSuccessful {
                let content = String(data: decryptResult.data!, encoding: .utf8)
                let isVerified = decryptResult.signatureValid
                
                if isVerified {
                    print("✅ Document verified and decrypted")
                    print("Signed by: \(decryptResult.signatureUser ?? "unknown")")
                } else {
                    print("⚠️ Document decrypted but signature not verified")
                }
                
                return (content: content, isVerified: isVerified)
            } else {
                print("❌ Failed to decrypt document: \(decryptResult.status ?? "unknown")")
                return (content: nil, isVerified: false)
            }
        } catch {
            print("❌ Error processing document: \(error)")
            return (content: nil, isVerified: false)
        }
    }
}

// Usage
func documentWorkflowExample() async {
    do {
        let manager = try SecureDocumentManager()
        
        let document = """
        CONFIDENTIAL MEMO
        
        Subject: Q4 Financial Results
        Date: \(Date())
        
        This document contains sensitive financial information...
        """
        
        let recipients = ["cfo@company.com", "ceo@company.com"]
        
        // Secure the document
        if let securedDocument = await manager.secureDocument(document, for: recipients) {
            print("📄 Document secured successfully")
            
            // Later, verify and decrypt
            let (decryptedContent, isVerified) = await manager.verifyAndDecrypt(securedDocument)
            
            if let content = decryptedContent, isVerified {
                print("📋 Document content verified:")
                print(content)
            } else {
                print("❌ Document verification failed")
            }
        }
        
    } catch {
        print("Error: \(error)")
    }
}
```

### Automated Backup Encryption

```swift
func automatedBackup() async {
    do {
        let gpg = try GnuPG()
        let backupRecipients = ["backup@company.com", "admin@company.com"]
        
        let filesToBackup = [
            "/important/database.sql",
            "/important/config.json", 
            "/important/certificates/"
        ]
        
        for filePath in filesToBackup {
            let filename = URL(fileURLWithPath: filePath).lastPathComponent
            print("🔄 Encrypting \(filename)...")
            
            let encryptResult = await gpg.encryptFile(
                filePath: filePath,
                recipients: backupRecipients,
                armor: true,
                outputPath: "/backups/\(filename).gpg"
            )
            
            if encryptResult.isSuccessful {
                print("✅ \(filename) encrypted successfully")
                
                // Verify the encrypted file can be decrypted
                let canDecrypt = await gpg.canDecryptFile(filePath: "/backups/\(filename).gpg")
                if canDecrypt {
                    print("✅ \(filename) backup verified")
                } else {
                    print("⚠️ \(filename) backup verification failed")
                }
            } else {
                print("❌ Failed to encrypt \(filename): \(encryptResult.status ?? "unknown")")
            }
        }
        
        print("🎯 Backup process completed")
        
    } catch {
        print("❌ Backup error: \(error)")
    }
}
```

This completes the comprehensive examples guide for the Swift GnuPG library, covering practical use cases from basic operations to real-world scenarios.

## See Also

- <doc:GettingStarted>
- <doc:GPGInstallation>
- <doc:API-Reference>
- <doc:Troubleshooting>
- ``GnuPG``
- ``GPGError``
- ``GPGLogger``

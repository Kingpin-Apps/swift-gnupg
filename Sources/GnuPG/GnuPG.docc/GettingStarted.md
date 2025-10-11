# Getting Started with Swift GnuPG

@Metadata {
   @PageKind(article)
   @PageColor(green)
   @CallToAction(url: "<doc:Examples>", purpose: link, label: "See More Examples")
}

Build your first Swift application using GnuPG for cryptographic operations.

## Overview

This guide walks you through creating your first Swift project with GnuPG support, from installation through basic operations like signing, encryption, and key management.

## Prerequisites

Before you begin, you'll need:

- **Swift 6.0+** with modern concurrency support
- **GnuPG 2.0+** installed on your system
- **Xcode 15.0+** (for macOS development) or Swift command-line tools

> Important: If you haven't installed GnuPG yet, follow the <doc:GPGInstallation> guide first.

## Step 1: Create Your Project

### Using Swift Package Manager

Create a new Swift package:

```bash
# Create project directory
mkdir MyGPGApp
cd MyGPGApp

# Initialize Swift package
swift package init --type executable
```

### Using Xcode

1. Open Xcode
2. Choose "Create a new Xcode project"
3. Select "macOS" > "Command Line Tool"
4. Choose "Swift" as the language
5. Name your project "MyGPGApp"

## Step 2: Add Swift GnuPG Dependency

### Package.swift Configuration

Edit your `Package.swift` file to include Swift GnuPG:

```swift
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MyGPGApp",
    platforms: [
        .macOS(.v10_15), // Required for async/await
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    dependencies: [
        .package(
            url: "https://github.com/Kingpin-Apps/swift-gnupg.git", 
            from: "0.1.0"
        )
    ],
    targets: [
        .executableTarget(
            name: "MyGPGApp",
            dependencies: [
                .product(name: "GnuPG", package: "swift-gnupg")
            ]
        )
    ]
)
```

### Xcode Integration

1. In Xcode, select your project in the navigator
2. Go to the "Package Dependencies" tab
3. Click the "+" button
4. Enter: `https://github.com/Kingpin-Apps/swift-gnupg.git`
5. Click "Add Package"

## Step 3: Your First GPG Application

Replace the contents of your `main.swift` (or create a new Swift file) with this example:

```swift
import Foundation
import GnuPG

// MARK: - Main Application

@main
struct MyGPGApp {
    static func main() async throws {
        print("🔐 Welcome to Swift GnuPG!")
        
        do {
            // Initialize GPG
            let gpg = try await initializeGPG()
            
            // Run basic operations
            try await exploreGPGOperations(gpg)
            
        } catch {
            print("❌ Error: \(error)")
            if let gpgError = error as? GPGError {
                print("💡 Suggestion: \(gpgError.recoverySuggestion ?? "Check GPG installation")")
            }
        }
    }
    
    // MARK: - GPG Initialization
    
    static func initializeGPG() async throws -> GnuPG {
        print("\n📋 Initializing GPG...")
        
        // Create GPG instance with verbose output for learning
        let gpg = try GnuPG(verbose: true)
        
        // Enable logging to see what's happening
        gpg.logger.level = .info
        gpg.logger.setConsoleLogging(enabled: true)
        
        // Display GPG information
        if let version = gpg.version {
            print("✅ GPG Version: \(version.major).\(version.minor)\(version.patch.map { ".\($0)" } ?? "")")
        }
        
        print("✅ GPG Binary: \(gpg.gpgBinary)")
        print("✅ GPG Home: \(gpg.gnupgHome ?? "default (~/.gnupg)")")
        
        return gpg
    }
    
    // MARK: - Basic Operations
    
    static func exploreGPGOperations(_ gpg: GnuPG) async throws {
        
        // 1. List available keys
        try await listKeys(gpg)
        
        // 2. Try basic signing (if keys are available)
        try await tryBasicOperations(gpg)
        
        // 3. Show configuration options
        showConfigurationExample(gpg)
        
        print("\n🎉 Tutorial complete! Check out the Examples documentation for more advanced usage.")
    }
}

// MARK: - Key Management

extension MyGPGApp {
    
    static func listKeys(_ gpg: GnuPG) async throws {
        print("\n📋 Listing Available Keys...")
        
        // List public keys
        let publicKeys = await gpg.listKeys()
        print("📄 Public Keys: \(publicKeys.keys.count)")
        
        for (index, key) in publicKeys.keys.prefix(3).enumerated() {
            print("  \(index + 1). \(key.keyId): \(key.userId ?? "No User ID")")
            print("     Type: \(key.type), Capabilities: \(key.capabilities ?? "unknown")")
            if key.isExpired {
                print("     ⚠️ EXPIRED")
            }
        }
        
        if publicKeys.keys.count > 3 {
            print("     ... and \(publicKeys.keys.count - 3) more")
        }
        
        // List secret keys
        let secretKeys = await gpg.listKeys(secretKeys: true)
        print("🔐 Secret Keys: \(secretKeys.keys.count)")
        
        if secretKeys.keys.isEmpty {
            print("   💡 No secret keys found. Generate one with: gpg --full-generate-key")
        } else {
            for key in secretKeys.keys.prefix(2) {
                print("   🔑 \(key.keyId): \(key.userId ?? "No User ID")")
            }
        }
    }
}

// MARK: - Basic Operations

extension MyGPGApp {
    
    static func tryBasicOperations(_ gpg: GnuPG) async throws {
        
        // Get available secret keys for operations
        let secretKeys = await gpg.listKeys(secretKeys: true)
        
        guard !secretKeys.keys.isEmpty else {
            print("\n⚠️ No secret keys available for signing operations")
            print("💡 Generate a key first: gpg --full-generate-key")
            return
        }
        
        let testKey = secretKeys.keys.first!
        print("\n🔐 Testing operations with key: \(testKey.keyId)")
        
        // Test signing
        try await testSigning(gpg, keyId: testKey.keyId)
        
        // Test encryption (to ourselves)
        if testKey.canEncrypt {
            try await testEncryption(gpg, recipient: testKey.keyId)
        }
    }
    
    static func testSigning(_ gpg: GnuPG, keyId: String) async throws {
        print("\n✍️ Testing Digital Signature...")
        
        let testMessage = "Hello from Swift GnuPG! Timestamp: \(Date())"
        
        // Sign the message
        let signResult = await gpg.sign(
            message: testMessage,
            keyId: keyId,
            armor: true
        )
        
        if signResult.isSuccessful {
            print("✅ Message signed successfully!")
            print("   Signature Key: \(signResult.keyId ?? "unknown")")
            print("   Hash Algorithm: \(signResult.hashAlgo ?? "unknown")")
            
            // Verify the signature
            if let signedData = signResult.data,
               let signedMessage = String(data: signedData, encoding: .utf8) {
                
                let verifyResult = await gpg.verify(message: signedMessage)
                print("✅ Signature verified: \(verifyResult.valid)")
            }
            
        } else {
            print("❌ Signing failed: \(signResult.status ?? "unknown error")")
        }
    }
    
    static func testEncryption(_ gpg: GnuPG, recipient: String) async throws {
        print("\n🔒 Testing Encryption...")
        
        let secretMessage = "This is a secret message encrypted at \(Date())"
        
        // Encrypt to ourselves
        let encryptResult = await gpg.encrypt(
            message: secretMessage,
            recipients: [recipient],
            armor: true
        )
        
        if encryptResult.isSuccessful {
            print("✅ Message encrypted successfully!")
            print("   Recipients: \(encryptResult.recipients.joined(separator: ", "))")
            
            // Try to decrypt it back
            if let encryptedData = encryptResult.data,
               let encryptedMessage = String(data: encryptedData, encoding: .utf8) {
                
                let decryptResult = await gpg.decrypt(message: encryptedMessage)
                
                if decryptResult.isSuccessful,
                   let decryptedData = decryptResult.data,
                   let decryptedMessage = String(data: decryptedData, encoding: .utf8) {
                    print("✅ Message decrypted successfully!")
                    print("   Content matches: \(decryptedMessage == secretMessage)")
                }
            }
            
        } else {
            print("❌ Encryption failed: \(encryptResult.status ?? "unknown error")")
            if !encryptResult.invalidRecipients.isEmpty {
                print("   Invalid recipients: \(encryptResult.invalidRecipients)")
            }
        }
    }
}

// MARK: - Configuration Examples

extension MyGPGApp {
    
    static func showConfigurationExample(_ gpg: GnuPG) {
        print("\n⚙️ Configuration Examples")
        print("Current GPG instance settings:")
        print("  • Binary path: \(gpg.gpgBinary)")
        print("  • Home directory: \(gpg.gnupgHome ?? "default")")
        print("  • Verbose mode: \(gpg.verbose)")
        print("  • Buffer size: \(gpg.bufferSize) bytes")
        
        print("\nTo customize GPG configuration:")
        print("""
        // Custom configuration example
        let customGPG = try GnuPG(
            gpgBinary: "/custom/path/gpg",
            gnupgHome: "~/.gnupg-custom",
            verbose: true,
            options: ["--cipher-algo", "AES256"]
        )
        
        // Enable detailed logging
        customGPG.logger.level = .debug
        """)
        
        print("\n🔍 Error Handling Pattern:")
        print("""
        do {
            let result = await gpg.sign(message: "test")
            if result.isSuccessful {
                // Process success
            } else {
                print("Operation failed: \\(result.status)")
            }
        } catch let error as GPGError {
            print("GPG Error: \\(error.errorDescription)")
            print("Suggestion: \\(error.recoverySuggestion)")
        }
        """)
    }
}
```

## Step 4: Run Your Application

### Using Swift Package Manager

```bash
# Build and run
swift run

# Or build first, then run
swift build
.build/debug/MyGPGApp
```

### Using Xcode

1. Press **⌘R** or click the "Run" button
2. View output in Xcode's console

## Expected Output

When you run the application, you should see output similar to:

```
🔐 Welcome to Swift GnuPG!

📋 Initializing GPG...
✅ GPG Version: 2.4.3
✅ GPG Binary: /opt/homebrew/bin/gpg
✅ GPG Home: default (~/.gnupg)

📋 Listing Available Keys...
📄 Public Keys: 2
  1. ABCD1234: John Doe <john@example.com>
     Type: pub, Capabilities: SC
  2. EFGH5678: Alice Smith <alice@example.com>
     Type: pub, Capabilities: SC

🔐 Secret Keys: 1
   🔑 ABCD1234: John Doe <john@example.com>

🔐 Testing operations with key: ABCD1234

✍️ Testing Digital Signature...
✅ Message signed successfully!
   Signature Key: ABCD1234
   Hash Algorithm: SHA256
✅ Signature verified: true

🔒 Testing Encryption...
✅ Message encrypted successfully!
   Recipients: ABCD1234
✅ Message decrypted successfully!
   Content matches: true

🎉 Tutorial complete!
```

## Understanding Async/Await

Swift GnuPG uses modern Swift concurrency. Key points:

### Async Functions

All GPG operations are `async` and must be called with `await`:

```swift
// ✅ Correct - using await
let keys = await gpg.listKeys()
let signResult = await gpg.sign(message: "test")

// ❌ Incorrect - missing await (won't compile)
let keys = gpg.listKeys()
```

### Async Context

Async functions must be called from async contexts:

```swift
// ✅ In async function
func myAsyncFunction() async throws {
    let gpg = try GnuPG()
    let result = await gpg.sign(message: "test")
}

// ✅ Using Task for non-async contexts
func mySyncFunction() throws {
    Task {
        let gpg = try GnuPG()
        let result = await gpg.sign(message: "test")
    }
}

// ✅ In @main with async
@main
struct App {
    static func main() async throws {
        // Async operations work here
    }
}
```

### Concurrent Operations

Run multiple operations simultaneously:

```swift
// Run operations concurrently
async let signTask = gpg.sign(message: "message1")
async let encryptTask = gpg.encrypt(message: "message2", recipients: ["user@example.com"])
async let listKeysTask = gpg.listKeys()

// Wait for results
let signResult = await signTask
let encryptResult = await encryptTask
let keysResult = await listKeysTask
```

## Common First Steps

### 1. Generate Your First Key (if needed)

If you don't have any GPG keys:

```bash
# Generate a test key
gpg --quick-generate-key "Test User <test@example.com>" default default 1y

# Or interactive key generation
gpg --full-generate-key
```

### 2. Import Sample Keys

For testing, you can import sample keys:

```bash
# Generate a test key and export it
gpg --quick-generate-key "Sample User <sample@test.com>" default default 1y
gpg --export --armor "sample@test.com" > sample_public.asc
gpg --export-secret-keys --armor "sample@test.com" > sample_secret.asc

# Later import on other systems
gpg --import sample_public.asc
gpg --import sample_secret.asc
```

### 3. Trust Keys for Testing

```bash
# Trust a key (be careful in production!)
gpg --edit-key test@example.com
# In GPG prompt: trust, then 5 (ultimate), y, quit
```

## Troubleshooting

### "GPG binary not available"

1. Verify GPG is installed: `gpg --version`
2. Check if GPG is in PATH: `which gpg`
3. See <doc:GPGInstallation> for installation help

### "No secret keys found"

1. Generate a key: `gpg --full-generate-key`
2. Or import existing keys: `gpg --import keyfile.asc`

### Permission denied errors

1. Check GPG directory permissions: `ls -la ~/.gnupg`
2. Fix permissions: `chmod 700 ~/.gnupg`

## Next Steps

Now that you have a working Swift GnuPG application:

1. Explore <doc:Examples> for more advanced usage patterns
2. Read the <doc:API-Reference> for complete API documentation
3. Check <doc:Troubleshooting> for common issues and solutions

## See Also

- <doc:Examples>
- <doc:GPGInstallation>
- <doc:API-Reference>
- <doc:Troubleshooting>
- ``GnuPG``
- ``GPGError``
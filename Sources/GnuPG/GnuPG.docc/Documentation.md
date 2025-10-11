# ``GnuPG``

@Metadata {
   @PageKind(article)
   @PageColor(blue)
   @CallToAction(url: "<doc:GettingStarted>", purpose: link, label: "Get Started")
   @Available(macOS, introduced: "10.15")
   @Available(iOS, introduced: "13.0")
   @Available(tvOS, introduced: "13.0")
   @Available(watchOS, introduced: "6.0")
}

A comprehensive Swift wrapper for GnuPG operations with modern async/await support.

## Overview

Swift GnuPG is a complete Swift library that provides a high-level, type-safe interface to GnuPG cryptographic operations. Built with Swift's modern concurrency model, it offers async/await support for all operations while maintaining compatibility with the proven python-gnupg API design.

### Key Features

- **Complete GPG Operations Suite**: Digital signatures, encryption/decryption, key management
- **Modern Swift Design**: Full async/await support with proper concurrency and Sendable compliance
- **Automatic Binary Discovery**: Finds GPG installations across macOS (Homebrew, MacPorts) and Linux
- **Comprehensive Error Handling**: Detailed error types with recovery suggestions
- **Production Ready**: Extensive test coverage with real GPG integration
- **Advanced Logging**: Multiple backends including Console and OSLog support

### System Requirements

- **Swift 6.0+** with modern concurrency support
- **macOS 10.15+**, **iOS 13.0+**, **tvOS 13.0+**, **watchOS 6.0+**, or **Linux**
- **GnuPG 2.0+** installed on the system (see <doc:GPGInstallation>)

### Quick Example

```swift
import GnuPG

// Initialize GPG (automatically discovers binary)
let gpg = try GnuPG()

// Sign a message
let signResult = await gpg.sign(message: "Hello, World!")
if signResult.isSuccessful {
    print("Message signed successfully!")
}

// List available keys
let keys = await gpg.listKeys()
print("Found \(keys.keys.count) public keys")
```

## Topics

### Getting Started

- <doc:GPGInstallation>
- <doc:GettingStarted>

### Core Operations

- <doc:Examples>
- ``GnuPG``

### Reference

- <doc:API-Reference>
- <doc:Troubleshooting>

### Result Types

- ``SignResult``
- ``VerifyResult``
- ``EncryptResult``
- ``DecryptResult``
- ``ListKeysResult``
- ``ImportResult``

### Error Handling

- ``GPGError``
- ``GPGLogger``

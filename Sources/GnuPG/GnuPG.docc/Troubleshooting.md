# Troubleshooting Swift GnuPG

@Metadata {
   @PageKind(article)
   @PageColor(red)
   @Available(macOS, introduced: "10.15")
}

Common issues and their solutions when using Swift GnuPG.

## Overview

This guide addresses the most common issues users encounter when working with Swift GnuPG, providing step-by-step solutions and prevention strategies.

## Installation Issues

### GPG Binary Not Available

**Error Message:**
```
GPG binary not available: gpg. Please install GPG or specify the correct path.
```

**Cause:** GnuPG is not installed or not found in the expected locations.

**Solutions:**

1. **Verify GPG Installation**
   ```bash
   # Check if GPG is installed
   gpg --version
   
   # Check if GPG is in PATH
   which gpg
   ```

2. **Install GPG** (see <doc:GPGInstallation> for detailed instructions)
   ```bash
   # macOS with Homebrew
   brew install gnupg
   
   # Ubuntu/Debian
   sudo apt install gnupg
   ```

3. **Specify Custom Path**
   ```swift
   // If GPG is in a custom location
   let gpg = try GnuPG(gpgBinary: "/custom/path/to/gpg")
   
   // Or use environment variable
   let gpgPath = ProcessInfo.processInfo.environment["GPG_BINARY"] ?? "gpg"
   let gpg = try GnuPG(gpgBinary: gpgPath)
   ```

### Invalid Home Directory

**Error Message:**
```
Invalid GPG home directory: /path/to/directory
```

**Cause:** The specified GPG home directory doesn't exist or isn't a directory.

**Solutions:**

1. **Create the Directory**
   ```bash
   mkdir -p ~/.gnupg-custom
   chmod 700 ~/.gnupg-custom
   ```

2. **Use Default Directory**
   ```swift
   // Let GPG use its default home directory
   let gpg = try GnuPG(gnupgHome: nil)
   ```

3. **Verify Directory Permissions**
   ```bash
   ls -la ~/.gnupg
   # Should show: drwx------
   ```

## Permission Issues

### GPG Directory Permission Denied

**Error Message:**
```
Permission denied for operation: signing
```

**Cause:** Incorrect permissions on GPG home directory or key files.

**Solutions:**

1. **Fix Directory Permissions**
   ```bash
   # Fix GPG home directory permissions
   chmod 700 ~/.gnupg
   chmod 600 ~/.gnupg/*
   
   # Or recursively
   chmod -R go-rwx ~/.gnupg
   ```

2. **Check Ownership**
   ```bash
   # Ensure you own the GPG directory
   ls -la ~/.gnupg
   
   # If not owned by you, fix it
   sudo chown -R $(whoami) ~/.gnupg
   ```

### Agent Socket Issues (macOS)

**Error Message:**
```
Can't connect to `/Users/username/.gnupg/S.gpg-agent': No such file or directory
```

**Solutions:**

1. **Restart GPG Agent**
   ```bash
   gpg-connect-agent reloadagent /bye
   ```

2. **Kill and Restart Agent**
   ```bash
   gpgconf --kill gpg-agent
   gpg-agent --daemon
   ```

## Key Management Issues

### Key Not Found

**Error Message:**
```
Key not found: user@example.com
```

**Cause:** The specified key doesn't exist in the keyring.

**Solutions:**

1. **List Available Keys**
   ```swift
   let keys = await gpg.listKeys()
   for key in keys.keys {
       print("\(key.keyId): \(key.userId ?? "No User ID")")
   }
   ```

2. **Import Missing Key**
   ```bash
   # Import from file
   gpg --import keyfile.asc
   
   # Import from keyserver
   gpg --keyserver keys.openpgp.org --recv-keys KEYID
   ```

3. **Use Correct Key Identifier**
   ```swift
   // Try different identifiers
   let result1 = await gpg.sign(message: "test", keyId: "user@example.com")
   let result2 = await gpg.sign(message: "test", keyId: "ABCD1234")      // Short ID
   let result3 = await gpg.sign(message: "test", keyId: "1234567890ABCDEF") // Long ID
   ```

### No Secret Key Available

**Error Message:**
```
No secret key available for signing
```

**Cause:** No private key available for the operation.

**Solutions:**

1. **Generate a New Key**
   ```bash
   gpg --full-generate-key
   ```

2. **Import Private Key**
   ```bash
   gpg --import private_key.asc
   ```

3. **Check Available Secret Keys**
   ```swift
   let secretKeys = await gpg.listKeys(secretKeys: true)
   print("Available secret keys: \(secretKeys.keys.count)")
   ```

### Key Expired

**Error Message:**
```
Key expired: ABCD1234
```

**Solutions:**

1. **Extend Key Expiration**
   ```bash
   gpg --edit-key KEYID
   # In GPG prompt: expire, then follow prompts
   ```

2. **Generate New Key**
   ```bash
   gpg --full-generate-key
   ```

## Cryptographic Operation Issues

### Invalid Passphrase

**Error Message:**
```
Invalid passphrase: contains newline or null characters
```

**Cause:** Passphrase contains invalid characters.

**Solutions:**

1. **Remove Invalid Characters**
   ```swift
   // Ensure passphrase doesn't contain newlines or null bytes
   let cleanPassphrase = passphrase.replacingOccurrences(of: "\n", with: "")
                                  .replacingOccurrences(of: "\0", with: "")
   
   let result = await gpg.sign(message: "test", passphrase: cleanPassphrase)
   ```

2. **Use Passphrase Validation**
   ```swift
   if GPGUtilities.isValidPassphrase(passphrase) {
       let result = await gpg.sign(message: "test", passphrase: passphrase)
   } else {
       print("Invalid passphrase format")
   }
   ```

### No Valid Recipients

**Error Message:**
```
No valid recipients found for encryption
```

**Cause:** None of the specified recipients have public keys available.

**Solutions:**

1. **Check Recipient Keys**
   ```swift
   let publicKeys = await gpg.listKeys()
   let availableRecipients = publicKeys.keys.compactMap { $0.userId }
   print("Available recipients: \(availableRecipients)")
   ```

2. **Import Recipient Keys**
   ```bash
   # Import recipient's public key
   gpg --import recipient_key.asc
   ```

3. **Use Key IDs Instead of Email**
   ```swift
   // Instead of email addresses, use key IDs
   let result = await gpg.encrypt(
       message: "secret",
       recipients: ["ABCD1234", "EFGH5678"]  // Key IDs
   )
   ```

### Signature Verification Failed

**Error Message:**
```
Signature verification failed
```

**Solutions:**

1. **Import Signer's Public Key**
   ```bash
   gpg --import signer_public_key.asc
   ```

2. **Check Message Integrity**
   ```swift
   // Ensure the signed message wasn't modified
   let verifyResult = await gpg.verify(message: originalSignedMessage)
   if !verifyResult.problems.isEmpty {
       print("Verification problems: \(verifyResult.problems)")
   }
   ```

3. **Trust the Signing Key**
   ```bash
   gpg --edit-key SIGNERS_KEY_ID
   # In GPG prompt: trust, then choose trust level
   ```

## Process and System Issues

### Process Launch Failed

**Error Message:**
```
Failed to launch GPG process: Operation not permitted
```

**Cause:** System security settings preventing process execution.

**Solutions:**

1. **macOS: Check Security Settings**
   - System Preferences > Security & Privacy > Privacy
   - Ensure Terminal/Xcode has necessary permissions

2. **Verify GPG Binary Permissions**
   ```bash
   ls -la $(which gpg)
   # Should be executable: -rwxr-xr-x
   ```

3. **Use Full Path**
   ```swift
   let fullPath = "/usr/local/bin/gpg"  // or other known path
   let gpg = try GnuPG(gpgBinary: fullPath)
   ```

### Process Timeout

**Error Message:**
```
Process timeout after 30 seconds
```

**Cause:** GPG operation taking longer than expected.

**Solutions:**

1. **Increase Buffer Size**
   ```swift
   let gpg = try GnuPG()
   gpg.bufferSize = 65536  // 64KB for large operations
   ```

2. **Disable GPG Agent for Batch Operations**
   ```swift
   let gpg = try GnuPG(useAgent: false)
   ```

3. **Use Async Operations Properly**
   ```swift
   // Don't block async operations
   async let result = gpg.encrypt(largeMessage, recipients: recipients)
   let encryptResult = await result
   ```

## Logging and Debugging

### Enable Detailed Logging

To better understand what's happening:

```swift
let gpg = try GnuPG(verbose: true)
gpg.logger.level = .debug
gpg.logger.setConsoleLogging(enabled: true)

// On macOS with OSLog
if #available(macOS 11.0, *) {
    gpg.logger.setOSLogging(enabled: true, subsystem: "com.myapp.gpg")
}
```

### Custom Debug Information

```swift
// Log operation timing
let result = await gpg.logger.logOperationAsync("Encryption") {
    return await gpg.encrypt(message: data, recipients: recipients)
}

// Check GPG command that was executed
gpg.logger.logCommand(gpg.makeArgs(["--version"]))
```

## Common Error Patterns

### Pattern: Check Before Operation

```swift
func safeGPGOperation() async throws {
    do {
        let gpg = try GnuPG()
        
        // Verify GPG is working
        guard gpg.version != nil else {
            throw GPGError.gpgNotAvailable(gpg.gpgBinary)
        }
        
        // Check for required keys
        let secretKeys = await gpg.listKeys(secretKeys: true)
        guard !secretKeys.keys.isEmpty else {
            print("No secret keys available. Generate one with: gpg --full-generate-key")
            return
        }
        
        // Proceed with operation
        let result = await gpg.sign(message: "test")
        
    } catch let error as GPGError {
        handleGPGError(error)
    }
}

func handleGPGError(_ error: GPGError) {
    print("GPG Error: \(error.errorDescription ?? "Unknown")")
    print("Suggestion: \(error.recoverySuggestion ?? "Check configuration")")
    
    switch error {
    case .gpgNotAvailable(let binary):
        print("Install GPG or check PATH. Missing: \(binary)")
    case .keyNotFound(let keyId):
        print("Import key \(keyId) or check identifier")
    case .noValidRecipients(let recipients):
        print("Import public keys for: \(recipients.joined(separator: ", "))")
    default:
        break
    }
}
```

## Frequently Asked Questions

### Q: Why doesn't Swift GnuPG work in iOS Simulator?

**A:** GPG requires command-line access which isn't available in iOS Simulator. Use on macOS or test on actual iOS devices (with limitations).

### Q: Can I use Swift GnuPG in a sandboxed application?

**A:** Limited support. Sandboxed apps have restricted process execution. Consider using CryptoKit for basic operations or request appropriate entitlements.

### Q: How do I handle multiple GPG home directories?

**A:** Create separate ``GnuPG`` instances:

```swift
let personalGPG = try GnuPG(gnupgHome: "~/.gnupg-personal")
let workGPG = try GnuPG(gnupgHome: "~/.gnupg-work")
```

### Q: Why do operations fail without error messages?

**A:** Enable verbose mode and logging:

```swift
let gpg = try GnuPG(verbose: true)
gpg.logger.level = .debug
gpg.logger.setConsoleLogging(enabled: true)
```

### Q: How do I handle operations that require user interaction?

**A:** Swift GnuPG is designed for batch operations. For interactive operations:

1. Pre-configure trust relationships
2. Use ``useAgent: false`` for non-interactive mode
3. Provide passphrases programmatically

## Performance Tips

### Optimize for Large Operations

```swift
// Increase buffer size for large files
gpg.bufferSize = 1048576  // 1MB

// Use concurrent operations
async let signTask = gpg.sign(message: data1)
async let encryptTask = gpg.encrypt(message: data2, recipients: recipients)

let results = await [signTask, encryptTask]
```

### Cache GPG Instance

```swift
// Don't create new instances frequently
class GPGManager {
    private let gpg: GnuPG
    
    init() throws {
        self.gpg = try GnuPG()
    }
    
    func performOperations() async {
        // Reuse the same instance
    }
}
```

## Getting Help

If you're still experiencing issues:

1. Check the <doc:Examples> for working code patterns
2. Review the <doc:API-Reference> for complete method signatures
3. Enable debug logging to understand what's happening
4. Verify your GPG installation works from command line
5. Check GitHub issues for similar problems

## See Also

- <doc:GPGInstallation>
- <doc:GettingStarted>
- <doc:Examples>
- <doc:API-Reference>
- ``GPGError``
- ``GPGLogger``
# Installing GnuPG

@Metadata {
   @PageKind(article)
   @PageColor(purple)
   @Available(macOS, introduced: "10.15")
}

Learn how to install and configure GnuPG as a prerequisite for using Swift GnuPG.

## Overview

Swift GnuPG requires a working installation of GnuPG (GNU Privacy Guard) on your system. The library acts as a Swift wrapper around the `gpg` command-line tool, providing a modern async/await interface while leveraging GnuPG's proven cryptographic implementations.

### Why GnuPG is Required

Swift GnuPG doesn't implement cryptographic operations directly. Instead, it:

- Spawns `gpg` processes to handle all cryptographic operations
- Parses GPG's status messages and output
- Provides type-safe Swift interfaces to GPG functionality
- Manages GPG process lifecycle and error handling

This approach ensures:
- **Security**: Relies on the well-audited GnuPG implementation
- **Compatibility**: Full compatibility with existing GPG keyrings and configurations
- **Features**: Access to all GPG capabilities including advanced options

## Installation Guide

### macOS Installation

#### Option 1: Homebrew (Recommended)

```bash
# Install GPG via Homebrew
brew install gnupg

# Verify installation
gpg --version
```

**Installation Paths:**
- **Apple Silicon Macs**: `/opt/homebrew/bin/gpg`
- **Intel Macs**: `/usr/local/bin/gpg`

#### Option 2: MacPorts

```bash
# Install GPG via MacPorts
sudo port install gnupg2

# Verify installation
gpg --version
```

**Installation Path:**
- `/opt/local/bin/gpg`

### Linux Installation

#### Ubuntu/Debian

```bash
# Update package list
sudo apt update

# Install GnuPG
sudo apt install gnupg

# Verify installation
gpg --version
```

#### RHEL/CentOS/Fedora

```bash
# RHEL/CentOS 7/8
sudo yum install gnupg2

# Fedora / RHEL 9+
sudo dnf install gnupg2

# Verify installation  
gpg --version
```

#### Arch Linux

```bash
# Install GnuPG (usually pre-installed)
sudo pacman -S gnupg

# Verify installation
gpg --version
```

### Verifying Installation

After installation, verify GnuPG is working correctly:

```bash
# Check GPG version (should show 2.0 or higher)
gpg --version

# Test basic functionality
gpg --list-keys

# Check if GPG is in PATH
which gpg
```

Expected output should show GnuPG version 2.0 or higher:
```
gpg (GnuPG) 2.4.3
libgcrypt 1.10.2
```

## Binary Discovery

Swift GnuPG automatically searches for the GPG binary in common locations:

### Search Order

1. **Specified Path**: If you provide a custom path via ``GnuPG/init(gpgBinary:)``
2. **PATH Lookup**: Uses `which gpg` to find binary in PATH
3. **Common Locations** (in order):
   - `/opt/homebrew/bin/gpg` (Homebrew on Apple Silicon)  
   - `/usr/local/bin/gpg` (Homebrew on Intel Mac)
   - `/usr/bin/gpg` (System installation)
   - `/opt/local/bin/gpg` (MacPorts)

### Custom Binary Path

If your GPG installation is in a non-standard location:

```swift
import GnuPG

// Specify custom GPG binary path
let gpg = try GnuPG(gpgBinary: "/custom/path/to/gpg")

// Or use environment variable
let customPath = ProcessInfo.processInfo.environment["GPG_BINARY"] ?? "gpg"
let gpg = try GnuPG(gpgBinary: customPath)
```

### Troubleshooting Discovery Issues

If Swift GnuPG cannot find your GPG installation:

1. **Check PATH**: Ensure `gpg` is in your PATH
   ```bash
   echo $PATH
   which gpg
   ```

2. **Verify Permissions**: Ensure the binary is executable
   ```bash
   ls -la $(which gpg)
   ```

3. **Test Manually**: Verify GPG works from command line
   ```bash
   gpg --version
   gpg --list-keys
   ```

## GPG Configuration

### First-Time Setup

After installation, GPG may need initial configuration:

```bash
# Generate your first key (optional)
gpg --full-generate-key

# Import existing keys
gpg --import /path/to/keyfile.asc

# List available keys
gpg --list-keys
gpg --list-secret-keys
```

### Home Directory

GPG stores keys and configuration in `~/.gnupg` by default. You can override this:

```swift
// Use custom GPG home directory
let gpg = try GnuPG(gnupgHome: "/path/to/custom/gnupg")
```

### Common Configuration

```bash
# Trust a key ultimately (for testing)
gpg --edit-key user@example.com
# In GPG prompt: trust, then 5 (ultimate), y, quit

# Set preferences in ~/.gnupg/gpg.conf
echo "armor" >> ~/.gnupg/gpg.conf
echo "use-agent" >> ~/.gnupg/gpg.conf
```

## Version Compatibility

### Supported Versions

- **Minimum**: GnuPG 2.0+
- **Recommended**: GnuPG 2.2+ for best compatibility
- **Latest**: GnuPG 2.4+ for newest features

### Version-Specific Features

Some features require specific GPG versions:

```swift
// Check detected GPG version
let gpg = try GnuPG()
if let version = gpg.version {
    print("GPG Version: \(version.major).\(version.minor)")
    
    // Version-specific logic
    if version >= GPGVersion(major: 2, minor: 1) {
        // Modern pinentry mode available
    }
}
```

## Testing Your Installation

Create a simple test to verify everything works:

```swift
import GnuPG

func testGPGInstallation() async throws {
    do {
        // Initialize GPG
        let gpg = try GnuPG(verbose: true)
        
        // Check version
        if let version = gpg.version {
            print("✅ GPG found: \(version.major).\(version.minor)")
        }
        
        // Test basic operations
        let keys = await gpg.listKeys()
        print("✅ Found \(keys.keys.count) keys in keyring")
        
        print("✅ Swift GnuPG ready to use!")
        
    } catch GPGError.gpgNotAvailable(let binary) {
        print("❌ GPG not found: \(binary)")
        print("Please install GnuPG following the guide above")
    } catch {
        print("❌ Error: \(error)")
    }
}

// Run the test
Task {
    try await testGPGInstallation()
}
```

## Next Steps

Once GnuPG is installed and working:

1. Continue to <doc:GettingStarted> for your first Swift GnuPG project
2. Explore <doc:Examples> for common usage patterns
3. Reference <doc:API-Reference> for complete API documentation

## See Also

- <doc:GettingStarted>
- <doc:Troubleshooting>
- ``GnuPG/init(gpgBinary:gnupgHome:keyring:secretKeyring:verbose:useAgent:options:environment:)``
- ``GPGError``
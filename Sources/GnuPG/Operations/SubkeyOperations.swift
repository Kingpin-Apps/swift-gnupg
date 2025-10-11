import Foundation

extension GnuPG {
    
    // MARK: - Subkey Operations
    
    /// Add a subkey to an existing master key
    /// - Parameters:
    ///   - masterKey: The master key fingerprint
    ///   - masterPassphrase: Passphrase for the master key
    ///   - algorithm: Key algorithm (e.g., "rsa", "dsa", "ecdsa")
    ///   - usage: Key usage (e.g., "sign", "encrypt", "auth")
    ///   - keySize: Key size in bits (optional, uses default for algorithm)
    ///   - expire: Expiration in days (0 for no expiration)
    /// - Returns: An ImportResult indicating success or failure
    @discardableResult
    public func addSubkey(masterKey: String,
                         masterPassphrase: String,
                         algorithm: String = "rsa",
                         usage: String = "sign",
                         keySize: Int? = nil,
                         expire: Int = 0) async -> ImportResult {
        
        let result = ImportResult(gpg: self)
        
        do {
            // Build key generation parameters
            var keySpec = ""
            
            // Key type based on algorithm and usage
            let keyType: String
            switch (algorithm.lowercased(), usage.lowercased()) {
            case ("rsa", "sign"):
                keyType = "4"  // RSA (sign only)
            case ("rsa", "encrypt"):
                keyType = "6"  // RSA (encrypt only)
            case ("dsa", "sign"):
                keyType = "17" // DSA (sign only)
            case ("ecdsa", "sign"):
                keyType = "22" // ECDSA (sign only)
            default:
                keyType = "4"  // Default to RSA sign
            }
            
            keySpec += "Key-Type: \(keyType)\n"
            
            // Key length
            if let size = keySize {
                keySpec += "Key-Length: \(size)\n"
            }
            
            // Subkey usage
            keySpec += "Key-Usage: \(usage)\n"
            
            // Expiration
            if expire > 0 {
                keySpec += "Expire-Date: \(expire)d\n"
            } else {
                keySpec += "Expire-Date: 0\n"
            }
            
            // Master key
            keySpec += "Master-Key: \(masterKey)\n"
            
            // Passphrase
            keySpec += "Passphrase: \(masterPassphrase)\n"
            
            // End marker
            keySpec += "%commit\n%echo done\n"
            
            let args = ["--batch", "--gen-key"]
            
            let processResult = try await self.executeCommand(
                arguments: args,
                input: keySpec.data(using: .utf8),
                statusHandler: result,
                passphrase: masterPassphrase
            )
            
            // Parse the output for the new subkey fingerprint
            if let output = processResult.output,
               let outputString = String(data: output, encoding: .utf8) {
                result.status = outputString
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
}
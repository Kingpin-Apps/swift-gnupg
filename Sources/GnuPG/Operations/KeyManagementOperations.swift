import Foundation

extension GnuPG {
    
    // MARK: - Key Management Operations
    
    /// Set trust level for keys
    /// - Parameters:
    ///   - fingerprints: Array of key fingerprints to trust
    ///   - trustLevel: The trust level to set
    /// - Returns: A GPGResult indicating success or failure
    @discardableResult
    public func trustKeys(_ fingerprints: [String], trustLevel: GPGTrust) async -> GPGResult {
        let result = GPGResult(gpg: self)
        
        do {
            for fingerprint in fingerprints {
                // Use --edit-key to set trust
                let trustCommand = "\(trustLevel.rawValue)\ny\nquit\n"
                
                let args = ["--batch", "--yes", "--command-fd", "0", "--edit-key", fingerprint, "trust"]
                
                _ = try await self.executeCommand(
                    arguments: args,
                    input: trustCommand.data(using: .utf8),
                    statusHandler: result
                )
                
                // Check if the operation succeeded
                if result.returnCode != 0 {
                    result.status = "Failed to set trust for key: \(fingerprint)"
                    break
                }
            }
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Delete public and/or secret keys
    /// - Parameters:
    ///   - keyIdentifier: Key fingerprint or ID to delete
    ///   - secret: Whether to delete secret key (default: false)
    ///   - passphrase: Passphrase for secret key deletion
    /// - Returns: A GPGResult indicating success or failure  
    @discardableResult
    public func deleteKeys(_ keyIdentifier: String, secret: Bool = false, passphrase: String? = nil) async -> GPGResult {
        let result = GPGResult(gpg: self)
        
        do {
            var args: [String]
            
            if secret {
                args = ["--batch", "--yes", "--delete-secret-keys", keyIdentifier]
            } else {
                args = ["--batch", "--yes", "--delete-keys", keyIdentifier]
            }
            
            _ = try await self.executeCommand(
                arguments: args,
                statusHandler: result,
                passphrase: passphrase
            )
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Delete both secret and public keys for a key identifier
    /// - Parameters:
    ///   - keyIdentifier: Key fingerprint or ID to delete
    ///   - passphrase: Passphrase for secret key deletion
    /// - Returns: A GPGResult indicating success or failure
    @discardableResult
    public func deleteSecretAndPublicKeys(_ keyIdentifier: String, passphrase: String? = nil) async -> GPGResult {
        // First delete secret key
        let secretResult = await deleteKeys(keyIdentifier, secret: true, passphrase: passphrase)
        guard secretResult.returnCode == 0 else {
            return secretResult
        }
        
        // Then delete public key
        return await deleteKeys(keyIdentifier, secret: false)
    }
}

// MARK: - Supporting Result Classes

/// Result class for general GPG operations
public class GPGResult: BaseStatusHandler, @unchecked Sendable {
    public var status: String?
    
    public override init(gpg: GnuPG) {
        super.init(gpg: gpg)
    }
    
    public override func handleStatus(key: String, value: String) {
        let statusMessage = "\(key): \(value)"
        
        if key.contains("ERROR") || key.contains("FAILURE") {
            self.returnCode = 2
        }
        
        if self.status == nil {
            self.status = statusMessage
        } else {
            self.status! += "\n" + statusMessage
        }
    }
    
    /// Description for compatibility
    public var description: String {
        return status ?? "Operation completed"
    }
}

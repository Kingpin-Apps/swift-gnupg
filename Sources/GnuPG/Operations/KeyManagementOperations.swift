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

        // Only certain levels are assignable as ownertrust; reject the rest
        // (unknown/revoked/disabled, e.g. from an invalid GPGTrust.custom(...)).
        guard let trustValue = trustLevel.ownertrustImportValue else {
            result.status = "error: invalid trust level"
            result.returnCode = 2
            return result
        }

        // Apply trust via `--import-ownertrust` rather than the interactive
        // `--edit-key trust` menu, which is unreliable in batch mode (it leaves
        // ownertrust unset). The input format is `<fingerprint>:<value>:` per line.
        let ownertrustInput = fingerprints
            .map { "\($0):\(trustValue):" }
            .joined(separator: "\n") + "\n"

        do {
            // Force the pgp trust model for this call. Callers (e.g. test setups)
            // may run with a global "--trust-model always", under which gpg never
            // creates a trustdb; --import-ownertrust then fails fatally because the
            // trustdb file doesn't exist. "--trust-model pgp" comes last, so it wins.
            _ = try await self.executeCommand(
                arguments: ["--trust-model", "pgp", "--import-ownertrust"],
                input: ownertrustInput.data(using: .utf8),
                statusHandler: result
            )

            if result.returnCode != 0 {
                result.status = "Failed to set trust"
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
    
    /// Human-readable reasons for the DELETE_PROBLEM status code.
    private static let deleteProblemReasons: [String: String] = [
        "1": "No such key",
        "2": "Must delete secret key first",
        "3": "Ambiguous specification"
    ]

    public override func handleStatus(key: String, value: String) {
        let statusMessage: String
        if key == "DELETE_PROBLEM" {
            statusMessage = GPGResult.deleteProblemReasons[value] ?? "Delete problem: \(value)"
            self.returnCode = 2
        } else {
            statusMessage = "\(key): \(value)"
        }

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

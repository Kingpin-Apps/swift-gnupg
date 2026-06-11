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
            // Use --quick-add-key (matching python-gnupg). This emits a
            // KEY_CREATED status line carrying the *subkey* fingerprint, which
            // ImportResult records, and reports an invalid algorithm with a
            // non-zero exit code rather than silently falling back to RSA.
            let expireSpec = expire > 0 ? "\(expire)d" : "0"
            let args = ["--quick-add-key", masterKey, algorithm, usage, expireSpec]

            _ = try await self.executeCommand(
                arguments: args,
                input: Data(),
                statusHandler: result,
                passphrase: masterPassphrase
            )

        } catch {
            result.status = "error: \(error.localizedDescription)"
        }

        return result
    }

    /// Delete a single subkey from a key, leaving the primary key intact.
    ///
    /// `--delete-keys`/`--delete-secret-keys` always remove the whole key, so a
    /// subkey is deleted via the `--edit-key` `delkey` command instead. A single
    /// edit removes the subkey from both the public and secret keyrings.
    /// - Parameters:
    ///   - masterFingerprint: Fingerprint (or key id) of the primary key.
    ///   - subkeyFingerprint: Fingerprint of the subkey to remove.
    ///   - passphrase: Passphrase for the key, if protected.
    /// - Returns: A GPGResult indicating success or failure.
    @discardableResult
    public func deleteSubkey(masterFingerprint: String,
                             subkeyFingerprint: String,
                             passphrase: String? = nil) async -> GPGResult {
        let result = GPGResult(gpg: self)

        // Locate the 1-based index of the subkey among the primary's subkeys;
        // `key N` in --edit-key selects subkeys in this same listing order.
        let listing = await listKeys(keys: [masterFingerprint])
        guard let master = listing.keys.first(where: { key in
            key.fingerprint == masterFingerprint
                || key.fingerprint?.hasSuffix(masterFingerprint) == true
                || masterFingerprint.hasSuffix(key.keyId)
        }) else {
            result.status = "error: master key not found"
            result.returnCode = 2
            return result
        }

        guard let position = master.subkeys.firstIndex(where: { subkey in
            let fpr = subkey.2
            return fpr == subkeyFingerprint
                || fpr.hasSuffix(subkeyFingerprint)
                || subkeyFingerprint.hasSuffix(subkey.0)
        }) else {
            result.status = "error: subkey not found"
            result.returnCode = 2
            return result
        }

        // key <n> selects the subkey, delkey removes it, y confirms, save commits.
        let commands = "key \(position + 1)\ndelkey\ny\nsave\n"
        do {
            _ = try await self.executeCommand(
                arguments: ["--command-fd", "0", "--edit-key", masterFingerprint],
                input: commands.data(using: .utf8),
                statusHandler: result,
                passphrase: passphrase
            )
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }

        return result
    }
}
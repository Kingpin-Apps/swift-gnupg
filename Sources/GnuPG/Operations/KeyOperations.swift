import Foundation

extension GnuPG {
    
    // MARK: - Key Operations
    
    /// List public keys in the keyring
    /// - Parameters:
    ///   - pattern: Optional pattern to filter keys (email, key ID, name, etc.)
    ///   - secretKeys: Whether to list secret keys instead of public keys (default: false)
    ///   - keys: Optional array of specific key IDs to list (alternative to pattern)
    ///   - sigs: Whether to list signatures (default: false)
    ///   - secret: Alternative parameter for secretKeys (for compatibility)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A ListKeysResult containing the found keys
    @discardableResult
    public func listKeys(pattern: String? = nil,
                        secretKeys: Bool = false,
                        keys: [String]? = nil,
                        sigs: Bool = false,
                        secret: Bool? = nil,
                        extraArgs: [String]? = nil) async -> ListKeysResult {
        
        let result = ListKeysResult(gpg: self)
        
        do {
            // Use secret parameter if provided, otherwise use secretKeys
            let useSecretKeys = secret ?? secretKeys
            
            var args: [String]
            if sigs {
                args = useSecretKeys ? ["--list-secret-keys", "--list-sigs"] : ["--list-public-keys", "--list-sigs"]
            } else {
                args = useSecretKeys ? ["--list-secret-keys"] : ["--list-public-keys"]
            }
            
            args.append(contentsOf: ["--with-colons", "--with-fingerprint"])
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            // Add specific keys if provided
            if let keyList = keys {
                args.append(contentsOf: keyList)
            } else if let pattern = pattern {
                args.append(pattern)
            }
            
            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result
            )
            
            // Parse the colon-delimited output
            if let outputData = processResult.output,
               let outputString = String(data: outputData, encoding: .utf8) {
                result.parseColonOutput(outputString)
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Import keys from data or file
    /// - Parameters:
    ///   - keyData: The key data to import (armored or binary)
    /// - Returns: An ImportResult indicating success and imported key details
    @discardableResult
    public func importKeys(keyData: Data) async -> ImportResult {
        let result = ImportResult(gpg: self)
        
        do {
            let args = ["--import"]
            
            _ = try await self.executeCommand(
                arguments: args,
                input: keyData,
                statusHandler: result
            )
            
            // ImportResult will process the status messages automatically
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Import keys from a string (armored format)
    /// - Parameters:
    ///   - keyString: The armored key data as a string
    /// - Returns: An ImportResult indicating success and imported key details
    @discardableResult
    public func importKeys(keyString: String) async -> ImportResult {
        guard let keyData = keyString.data(using: .utf8) else {
            let result = ImportResult(gpg: self)
            result.status = "error: failed to convert key string to data"
            return result
        }
        
        return await importKeys(keyData: keyData)
    }
    
    /// Import keys from a file
    /// - Parameters:
    ///   - filePath: Path to the key file to import
    /// - Returns: An ImportResult indicating success and imported key details
    @discardableResult
    public func importKeysFromFile(filePath: String) async -> ImportResult {
        let result = ImportResult(gpg: self)
        
        do {
            // Check if file exists
            guard FileManager.default.fileExists(atPath: filePath) else {
                result.status = "error: key file not found: \(filePath)"
                return result
            }
            
            let args = ["--import", filePath]
            
            _ = try await self.executeCommand(
                arguments: args,
                statusHandler: result
            )
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Export public keys
    /// - Parameters:
    ///   - keyId: The key ID or pattern to export (if nil, exports all keys)
    ///   - armor: Whether to export in ASCII armored format (default: true)
    /// - Returns: The exported key data, or nil if export failed
    public func exportKeys(keyId: String? = nil,
                          armor: Bool = true) async -> Data? {
        
        do {
            var args = ["--export"]
            
            if armor {
                args.append("--armor")
            }
            
            if let keyId = keyId {
                args.append(keyId)
            }
            
            let result = BaseStatusHandler(gpg: self)
            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result
            )
            
            return processResult.output
            
        } catch {
            return nil
        }
    }
    
    /// Export secret keys
    /// - Parameters:
    ///   - keyId: The key ID or pattern to export (if nil, exports all secret keys)
    ///   - armor: Whether to export in ASCII armored format (default: true)
    ///   - passphrase: Optional passphrase for key protection
    /// - Returns: The exported secret key data, or nil if export failed
    public func exportSecretKeys(keyId: String? = nil,
                                armor: Bool = true,
                                passphrase: String? = nil) async -> Data? {
        
        do {
            var args = ["--export-secret-keys"]
            
            if armor {
                args.append("--armor")
            }
            
            if let keyId = keyId {
                args.append(keyId)
            }
            
            let result = BaseStatusHandler(gpg: self)
            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result,
                passphrase: passphrase
            )
            
            return processResult.output
            
        } catch {
            return nil
        }
    }
    
    /// Export keys with additional options for backward compatibility
    /// - Parameters:
    ///   - keyId: The key ID or pattern to export
    ///   - secret: Whether to export secret keys (default: false)
    ///   - armor: Whether to export in ASCII armored format (default: true)
    ///   - passphrase: Optional passphrase for secret key export
    /// - Returns: The exported key data, or nil if export failed
    public func exportKeys(_ keyId: String, secret: Bool, armor: Bool = true, passphrase: String? = nil) async -> Data? {
        if secret {
            return await exportSecretKeys(keyId: keyId, armor: armor, passphrase: passphrase)
        } else {
            return await exportKeys(keyId: keyId, armor: armor)
        }
    }
    
    /// Delete a public key from the keyring
    /// - Parameters:
    ///   - keyId: The key ID or fingerprint to delete
    ///   - force: Whether to force deletion without confirmation (default: false)
    /// - Returns: True if deletion was successful, false otherwise
    @discardableResult
    public func deleteKey(keyId: String, force: Bool = false) async -> Bool {
        do {
            var args = ["--delete-key"]
            
            if force {
                args.append("--yes")
            }
            
            args.append(keyId)
            
            let result = BaseStatusHandler(gpg: self)
            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result
            )
            
            return processResult.exitCode == 0
            
        } catch {
            return false
        }
    }
    
    /// Delete a secret key from the keyring
    /// - Parameters:
    ///   - keyId: The key ID or fingerprint to delete
    ///   - force: Whether to force deletion without confirmation (default: false)
    /// - Returns: True if deletion was successful, false otherwise
    @discardableResult
    public func deleteSecretKey(keyId: String, force: Bool = false) async -> Bool {
        do {
            var args = ["--delete-secret-key"]
            
            if force {
                args.append("--yes")
            }
            
            args.append(keyId)
            
            let result = BaseStatusHandler(gpg: self)
            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result
            )
            
            return processResult.exitCode == 0
            
        } catch {
            return false
        }
    }
    
    /// Generate a new key pair
    /// - Parameters:
    ///   - keyType: Type of key to generate (e.g., "RSA", "DSA", "ECDSA")
    ///   - keySize: Size of the key in bits
    ///   - userId: User ID for the key (name and email)
    ///   - passphrase: Passphrase to protect the secret key
    ///   - expirationDate: Optional expiration date (e.g., "1y", "6m", "2025-12-31")
    /// - Returns: An ImportResult-like result indicating key generation status
    @discardableResult
    public func generateKey(keyType: String = "RSA",
                           keySize: Int = 3072,
                           userId: String,
                           passphrase: String,
                           expirationDate: String? = nil) async -> ImportResult {
        
        let result = ImportResult(gpg: self)
        
        do {
            // Create key generation parameters
            let keyParams = """
            %echo Generating key
            Key-Type: \(keyType)
            Key-Length: \(keySize)
            Name-Real: \(userId)
            Expire-Date: \(expirationDate ?? "0")
            Passphrase: \(passphrase)
            %commit
            %echo done
            """
            
            guard let keyParamsData = keyParams.data(using: .utf8) else {
                result.status = "error: failed to create key generation parameters"
                return result
            }
            
            let args = ["--batch", "--generate-key"]
            
            _ = try await self.executeCommand(
                arguments: args,
                input: keyParamsData,
                statusHandler: result
            )
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Convenience method to find a key by email or key ID
    /// - Parameters:
    ///   - identifier: Email address, key ID, or name to search for
    ///   - secretKeys: Whether to search in secret keys (default: false)
    /// - Returns: The first matching GPGKey, or nil if not found
    public func findKey(byIdentifier identifier: String,
                       secretKeys: Bool = false) async -> GPGKey? {
        let result = await listKeys(pattern: identifier, secretKeys: secretKeys)
        return result.keys.first
    }
    
    /// Get detailed information about a specific key
    /// - Parameters:
    ///   - keyId: The key ID or fingerprint to get information for
    /// - Returns: The GPGKey information, or nil if not found
    public func getKeyInfo(keyId: String) async -> GPGKey? {
        let result = await listKeys(pattern: keyId)
        return result.findKey(byId: keyId)
    }
    
    /// Check if a key exists in the keyring
    /// - Parameters:
    ///   - keyId: The key ID or fingerprint to check
    ///   - secretKeys: Whether to check in secret keys (default: false)
    /// - Returns: True if the key exists, false otherwise
    public func keyExists(keyId: String, secretKeys: Bool = false) async -> Bool {
        let key = await findKey(byIdentifier: keyId, secretKeys: secretKeys)
        return key != nil
    }
    
    /// Generate key input parameters for GPG key generation
    /// - Parameters:
    ///   - nameEmail: Email address for the key
    ///   - nameReal: Real name for the key (optional)
    ///   - nameComment: Comment for the key (optional)
    ///   - passphrase: Passphrase to protect the key (optional)
    ///   - keyType: Type of key (default: "RSA")
    ///   - keyLength: Key length in bits (default: 3072)
    ///   - expire: Expiration date (default: "0" for no expiration)
    /// - Returns: Generated key input string
    public func generateKeyInput(
        nameEmail: String,
        nameReal: String? = nil,
        nameComment: String? = nil,
        passphrase: String? = nil,
        keyType: String = "RSA",
        keyLength: Int = 3072,
        expire: String = "0"
    ) throws -> String {
        var keySpec = "%echo Generating key\n"
        keySpec += "Key-Type: \(keyType)\n"
        
        // ECDSA keys use curves, not key lengths
        if !keyType.uppercased().contains("ECDSA") && !keyType.uppercased().contains("ECDH") {
            keySpec += "Key-Length: \(keyLength)\n"
        }
        
        if let realName = nameReal {
            keySpec += "Name-Real: \(realName)\n"
        }
        
        if let comment = nameComment {
            keySpec += "Name-Comment: \(comment)\n"
        }
        
        keySpec += "Name-Email: \(nameEmail)\n"
        keySpec += "Expire-Date: \(expire)\n"
        
        if let passphrase = passphrase {
            keySpec += "Passphrase: \(passphrase)\n"
        }
        
        keySpec += "%commit\n%echo done\n"
        
        return keySpec
    }
    
    /// Generate key input with parameters object
    /// - Parameters:
    ///   - params: KeyGenParams object with generation parameters
    /// - Returns: Generated key input string
    public func generateKeyInput(params: KeyGenParams) throws -> String {
        let keyType = (params.keyType?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false) ? params.keyType!.trimmingCharacters(in: .whitespacesAndNewlines) : "RSA"
        let isECDSAKey = keyType.uppercased().contains("ECDSA") || keyType.uppercased().contains("ECDH")
        
        var keySpec = "%echo Generating key\n"
        keySpec += "Key-Type: \(keyType)\n"
        
        // ECDSA keys use curves, not key lengths
        if !isECDSAKey {
            keySpec += "Key-Length: \(params.keyLength ?? 3072)\n"
        }
        
        // Add curve for ECDSA keys
        if isECDSAKey, let keyCurve = params.keyCurve {
            keySpec += "Key-Curve: \(keyCurve)\n"
        }
        
        if let realName = params.nameReal {
            keySpec += "Name-Real: \(realName)\n"
        }
        
        if let comment = params.nameComment {
            keySpec += "Name-Comment: \(comment)\n"
        }
        
        keySpec += "Name-Email: \(params.nameEmail ?? "")\n"
        keySpec += "Expire-Date: \(params.expire ?? "0")\n"
        
        // Add subkey for ECDSA
        if isECDSAKey {
            keySpec += "Subkey-Type: ECDH\n"
            if let subkeyCurve = params.subkeyCurve {
                keySpec += "Subkey-Curve: \(subkeyCurve)\n"
            }
        }
        
        if let passphrase = params.passphrase {
            keySpec += "Passphrase: \(passphrase)\n"
        }
        
        keySpec += "%commit\n%echo done\n"
        
        return keySpec
    }
}

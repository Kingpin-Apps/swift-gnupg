import Foundation

extension GnuPG {
    
    // MARK: - Key Scanning Operations
    
    /// Scan keys from a file without importing them
    /// - Parameters:
    ///   - filePath: Path to the key file to scan
    /// - Returns: A ListKeysResult with the scanned key information
    @discardableResult
    public func scanKeys(_ filePath: String) async -> ListKeysResult {
        let result = ListKeysResult(gpg: self)
        
        do {
            // Check if file exists
            guard FileManager.default.fileExists(atPath: filePath) else {
                result.status = "error: key file not found: \(filePath)"
                return result
            }
            
            let args = ["--import-options", "show-only", "--import", filePath]
            
            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result
            )
            
            // Parse the output similar to listKeys
            if let outputData = processResult.output,
               let outputString = String(data: outputData, encoding: .utf8) {
                result.parseColonOutput(outputString)
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Scan keys from memory without importing them
    /// - Parameters:
    ///   - keyData: The key data as a string
    /// - Returns: A ListKeysResult with the scanned key information
    @discardableResult
    public func scanKeysFromMemory(_ keyData: String) async -> ListKeysResult {
        let result = ListKeysResult(gpg: self)
        
        do {
            let args = ["--import-options", "show-only", "--import"]
            
            let processResult = try await self.executeCommand(
                arguments: args,
                input: keyData.data(using: .utf8),
                statusHandler: result
            )
            
            // Parse the output similar to listKeys
            if let outputData = processResult.output,
               let outputString = String(data: outputData, encoding: .utf8) {
                result.parseColonOutput(outputString)
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    // MARK: - Keyserver Operations
    
    /// Receive keys from a keyserver
    /// - Parameters:
    ///   - keyserver: The keyserver URL
    ///   - keyIds: Array of key IDs to receive
    /// - Returns: An ImportResult indicating success and imported key details
    @discardableResult
    public func receiveKeys(_ keyserver: String, _ keyIds: String...) async -> ImportResult {
        let result = ImportResult(gpg: self)
        
        do {
            var args = ["--keyserver", keyserver, "--recv-keys"]
            args.append(contentsOf: keyIds)
            
            _ = try await self.executeCommand(
                arguments: args,
                statusHandler: result
            )
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Search for keys on a keyserver
    /// - Parameters:
    ///   - keyserver: The keyserver URL
    ///   - searchTerms: Array of search terms
    /// - Returns: A ListKeysResult with found keys
    @discardableResult
    public func searchKeys(_ keyserver: String, _ searchTerms: String...) async -> ListKeysResult {
        let result = ListKeysResult(gpg: self)
        
        do {
            var args = ["--keyserver", keyserver, "--search-keys"]
            args.append(contentsOf: searchTerms)
            
            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result
            )
            
            // Parse the keyserver search results (a distinct colon format).
            if let outputData = processResult.output,
               let outputString = String(data: outputData, encoding: .utf8) {
                result.parseSearchOutput(outputString)
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    // MARK: - Recipient Analysis
    
    /// Get recipients from encrypted data
    /// - Parameters:
    ///   - data: The encrypted data
    /// - Returns: Array of recipient key IDs
    public func getRecipients(_ data: Data) async -> [String] {
        do {
            let args = ["--list-only", "--decrypt"]
            
            let result = BaseStatusHandler(gpg: self)
            let processResult = try await self.executeCommand(
                arguments: args,
                input: data,
                statusHandler: result
            )
            
            // Parse recipients from status messages (ENC_TO)
            var recipients: [String] = []
            for message in result.statusMessages {
                if message.hasPrefix("ENC_TO ") {
                    let components = message.components(separatedBy: " ")
                    if components.count > 1 {
                        let keyId = components[1]
                        recipients.append(keyId)
                    }
                }
            }
            
            // If no recipients found in status messages, try parsing output
            if recipients.isEmpty {
                if let outputData = processResult.output,
                   let outputString = String(data: outputData, encoding: .utf8) {
                    recipients = parseRecipients(from: outputString)
                }
            }
            
            return recipients
            
        } catch {
            // Return empty array on error
        }
        
        return []
    }
    
    /// Get recipients from encrypted file
    /// - Parameters:
    ///   - filePath: Path to the encrypted file
    /// - Returns: Array of recipient key IDs
    public func getRecipientsFromFile(_ filePath: String) async -> [String] {
        guard FileManager.default.fileExists(atPath: filePath) else {
            return []
        }
        
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: filePath))
            return await getRecipients(data)
        } catch {
            return []
        }
    }
    
    /// Auto-locate and import a key
    /// - Parameters:
    ///   - keyId: The key ID or email to locate
    /// - Returns: An ImportResult indicating success
    @discardableResult
    public func autoLocateKey(_ keyId: String) async -> ImportResult {
        let result = ImportResult(gpg: self)
        
        do {
            let args = ["--auto-key-locate", "keyserver", "--locate-keys", keyId]
            
            _ = try await self.executeCommand(
                arguments: args,
                statusHandler: result
            )
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    // MARK: - Helper Methods
    
    private func parseRecipients(from output: String) -> [String] {
        let lines = output.components(separatedBy: .newlines)
        var recipients: [String] = []
        
        for line in lines {
            if line.contains("encrypted with") {
                // Extract key ID from line like "encrypted with 2048-bit RSA key, ID 1234ABCD"
                let components = line.components(separatedBy: "ID ")
                if components.count > 1 {
                    let keyId = components[1].trimmingCharacters(in: .whitespaces)
                    recipients.append(keyId)
                }
            }
        }
        
        return recipients
    }
}

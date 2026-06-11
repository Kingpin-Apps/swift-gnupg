import Foundation

extension GnuPG {
    
    // MARK: - Sign Operations
    
    /// Sign data using a specified key
    /// - Parameters:
    ///   - message: The data to sign as a String
    ///   - keyId: The ID of the key to use for signing (optional)
    ///   - passphrase: The passphrase for the signing key (optional)
    ///   - clearsign: Whether to create a clear signature (default: false)
    ///   - detach: Whether to create a detached signature (default: true)
    ///   - binary: Whether to create a binary signature (default: false)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A SignResult indicating success or failure
    @discardableResult
    public func sign(message: String,
                    keyId: String? = nil,
                    passphrase: String? = nil,
                    clearsign: Bool = true,
                    detach: Bool = false,
                    binary: Bool = false,
                    extraArgs: [String]? = nil) async -> SignResult {

        let result = SignResult(gpg: self)

        do {
            var args = ["--sign"]

            // Add signature type options. A detached signature can't be verified
            // without the original data, so the default is an embedded signature
            // (clearsign), matching python-gnupg.
            if detach {
                args[0] = "--detach-sign"
            } else if clearsign {
                args[0] = "--clearsign"
            }

            // ASCII-armor unless a binary signature was requested
            if !binary {
                args.append("--armor")
            }

            // Add key ID if specified
            if let keyId = keyId {
                args.append(contentsOf: ["--local-user", keyId])
            }
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            let process = try await self.executeCommand(
                arguments: args,
                input: message.data(using: .utf8),
                statusHandler: result,
                passphrase: passphrase
            )
            
            // Store the signed data if successful
            if let output = process.output {
                result.data = output
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Sign data from a Data object
    /// - Parameters:
    ///   - data: The data to sign
    ///   - keyId: The ID of the key to use for signing (optional)
    ///   - passphrase: The passphrase for the signing key (optional)
    ///   - clearsign: Whether to create a clear signature (default: false)
    ///   - detach: Whether to create a detached signature (default: true)
    ///   - binary: Whether to create a binary signature (default: false)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A SignResult indicating success or failure
    @discardableResult
    public func sign(data: Data,
                    keyId: String? = nil,
                    passphrase: String? = nil,
                    clearsign: Bool = true,
                    detach: Bool = false,
                    binary: Bool = false,
                    extraArgs: [String]? = nil) async -> SignResult {

        let result = SignResult(gpg: self)

        do {
            var args = ["--sign"]

            // Add signature type options. A detached signature can't be verified
            // without the original data, so the default is an embedded signature
            // (clearsign), matching python-gnupg.
            if detach {
                args[0] = "--detach-sign"
            } else if clearsign {
                args[0] = "--clearsign"
            }

            // ASCII-armor unless a binary signature was requested
            if !binary {
                args.append("--armor")
            }

            // Add key ID if specified
            if let keyId = keyId {
                args.append(contentsOf: ["--local-user", keyId])
            }
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            let process = try await self.executeCommand(
                arguments: args,
                input: data,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // Store the signed data if successful
            if let output = process.output {
                result.data = output
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Sign a file
    /// - Parameters:
    ///   - inputPath: Path to the file to sign
    ///   - outputPath: Optional path for the signed output (if nil, creates inputPath.asc or inputPath.sig)
    ///   - keyId: The ID of the key to use for signing (optional)
    ///   - passphrase: The passphrase for the signing key (optional)
    ///   - clearsign: Whether to create a clear signature (default: false)
    ///   - detach: Whether to create a detached signature (default: true)
    ///   - binary: Whether to create a binary signature (default: false)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A SignResult indicating success or failure
    @discardableResult
    public func signFile(inputPath: String,
                        outputPath: String? = nil,
                        keyId: String? = nil,
                        passphrase: String? = nil,
                        clearsign: Bool = true,
                        detach: Bool = false,
                        binary: Bool = false,
                        extraArgs: [String]? = nil) async -> SignResult {

        let result = SignResult(gpg: self)

        do {
            // Check if input file exists
            guard FileManager.default.fileExists(atPath: inputPath) else {
                result.status = "error: input file not found: \(inputPath)"
                return result
            }

            var args = ["--sign"]

            if detach {
                args[0] = "--detach-sign"
            } else if clearsign {
                args[0] = "--clearsign"
            }

            // ASCII-armor unless a binary signature was requested
            if !binary {
                args.append("--armor")
            }

            // Add key ID if specified
            if let keyId = keyId {
                args.append(contentsOf: ["--local-user", keyId])
            }

            // Direct the signature to an explicit file (--yes allows overwriting)
            // or to stdout ("-") so it is captured in `result.data`. Without an
            // explicit --output, gpg would write a sidecar file next to the input
            // ("input.asc"), which yields no `.data` and collides on re-signing.
            if let outputPath = outputPath {
                args.append(contentsOf: ["--yes", "--output", outputPath])
            } else {
                args.append(contentsOf: ["--output", "-"])
            }

            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }

            // Pass the file as a positional argument so gpg reads it directly from
            // disk. Streaming a large file through stdin instead would deadlock:
            // executeCommand writes all input before reading stdout, so once gpg's
            // output pipe fills it stops draining stdin and both sides block.
            args.append(inputPath)

            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result,
                passphrase: passphrase
            )

            // When no output file was requested, the signature is on stdout
            if outputPath == nil, let output = processResult.output {
                result.data = output
            }

        } catch {
            result.status = "error: \(error.localizedDescription)"
        }

        return result
    }
}
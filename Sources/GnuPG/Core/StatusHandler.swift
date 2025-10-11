import Foundation

// MARK: - StatusHandler Protocol

/// Base protocol for handling status messages from `gpg`.
/// 
/// This protocol defines the interface for processing status messages that GPG sends
/// to stderr in the format: [GNUPG:] <key> <value>
public protocol StatusHandler: AnyObject, Sendable {
    /// Reference to the GPG instance
    var gpg: GnuPG { get }
    
    /// Raw data returned from GPG operation
    var data: Data? { get set }
    
    /// Stderr output from GPG
    var stderr: String { get set }
    
    /// Return code from GPG process
    var returnCode: Int32? { get set }
    
    /// Handle a status message from GPG
    /// - Parameters:
    ///   - key: The status message key (e.g., "GOODSIG", "BADSIG")
    ///   - value: The status message value
    func handleStatus(key: String, value: String)
}

// MARK: - Base StatusHandler Implementation

/// Base implementation of StatusHandler protocol
open class BaseStatusHandler: StatusHandler, @unchecked Sendable {
    public let gpg: GnuPG
    public var data: Data?
    public var stderr: String = ""
    public var returnCode: Int32?
    public var onDataFailure: Error?
    
    /// Array to track status messages for advanced operations
    public var statusMessages: [String] = []
    
    public init(gpg: GnuPG) {
        self.gpg = gpg
    }
    
    /// Default implementation - subclasses should override
    open func handleStatus(key: String, value: String) {
        // Store the full status message for later parsing
        statusMessages.append("\(key) \(value)")
    }
}
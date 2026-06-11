import Foundation
#if canImport(os)
import os
#endif

/// Logging levels for GPG operations
public enum GPGLogLevel: Int, CaseIterable, Comparable, Sendable {
    case debug = 0
    case info = 1
    case warning = 2
    case error = 3
    case critical = 4
    
    public static func < (lhs: GPGLogLevel, rhs: GPGLogLevel) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }
    
    public var description: String {
        switch self {
        case .debug: return "DEBUG"
        case .info: return "INFO"
        case .warning: return "WARNING"
        case .error: return "ERROR"
        case .critical: return "CRITICAL"
        }
    }
    
    public var emoji: String {
        switch self {
        case .debug: return "🔍"
        case .info: return "ℹ️"
        case .warning: return "⚠️"
        case .error: return "❌"
        case .critical: return "🚨"
        }
    }
}

/// Protocol for custom log handlers
public protocol GPGLogHandler {
    func log(level: GPGLogLevel, message: String, category: String, file: String, function: String, line: Int)
}

/// Default console log handler
public struct GPGConsoleLogHandler: GPGLogHandler {
    private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return formatter
    }()
    
    public func log(level: GPGLogLevel, message: String, category: String, file: String, function: String, line: Int) {
        let timestamp = dateFormatter.string(from: Date())
        let filename = URL(fileURLWithPath: file).lastPathComponent
        let logMessage = "\(timestamp) \(level.emoji) [\(level.description)] \(category) - \(message) (\(filename):\(line) \(function))"
        print(logMessage)
    }
}

#if canImport(os)
/// OSLog-based log handler for better integration with Apple's logging system
@available(macOS 11.0, iOS 14.0, watchOS 7.0, tvOS 14.0, *)
public struct GPGOSLogHandler: GPGLogHandler {
    private let logger: os.Logger
    
    public init(subsystem: String = "com.gnupg.swift", category: String = "GPG") {
        self.logger = os.Logger(subsystem: subsystem, category: category)
    }
    
    public func log(level: GPGLogLevel, message: String, category: String, file: String, function: String, line: Int) {
        let filename = URL(fileURLWithPath: file).lastPathComponent
        let logMessage = "\(category) - \(message) (\(filename):\(line) \(function))"
        
        switch level {
        case .debug:
            logger.debug("\(logMessage, privacy: .public)")
        case .info:
            logger.info("\(logMessage, privacy: .public)")
        case .warning:
            logger.notice("\(logMessage, privacy: .public)")
        case .error:
            logger.error("\(logMessage, privacy: .public)")
        case .critical:
            logger.critical("\(logMessage, privacy: .public)")
        }
    }
}
#endif

/// Main logging class for GPG operations
public final class GPGLogger: @unchecked Sendable {
    public static let shared = GPGLogger()
    
    private let queue = DispatchQueue(label: "com.gnupg.swift.logger", qos: .utility)
    private var _handlers: [GPGLogHandler] = []
    private var _level: GPGLogLevel = .info
    private var _isEnabled: Bool = true
    
    public var level: GPGLogLevel {
        get { queue.sync { _level } }
        set { queue.sync { _level = newValue } }
    }
    
    public var isEnabled: Bool {
        get { queue.sync { _isEnabled } }
        set { queue.sync { _isEnabled = newValue } }
    }
    
    private init() {
        // Default to console logging
        _handlers = [GPGConsoleLogHandler()]
    }
    
    public func addHandler(_ handler: GPGLogHandler) {
        queue.sync {
            _handlers.append(handler)
        }
    }
    
    public func removeAllHandlers() {
        queue.sync {
            _handlers.removeAll()
        }
    }
    
    public func setConsoleLogging(enabled: Bool) {
        queue.sync {
            _handlers.removeAll { $0 is GPGConsoleLogHandler }
            if enabled {
                _handlers.append(GPGConsoleLogHandler())
            }
        }
    }
    
    #if canImport(os)
    @available(macOS 11.0, iOS 14.0, watchOS 7.0, tvOS 14.0, *)
    public func setOSLogging(enabled: Bool, subsystem: String = "com.gnupg.swift", category: String = "GPG") {
        queue.sync {
            _handlers.removeAll { $0 is GPGOSLogHandler }
            if enabled {
                _handlers.append(GPGOSLogHandler(subsystem: subsystem, category: category))
            }
        }
    }
    #endif
    
    public func log(
        level: GPGLogLevel,
        message: String,
        category: String = "GPG",
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        queue.async { [weak self] in
            guard let self = self, 
                  self._isEnabled,
                  level >= self._level else { return }
            
            for handler in self._handlers {
                handler.log(level: level, message: message, category: category, file: file, function: function, line: line)
            }
        }
    }
    
    // Convenience methods
    public func debug(
        _ message: String,
        category: String = "GPG",
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(level: .debug, message: message, category: category, file: file, function: function, line: line)
    }
    
    public func info(
        _ message: String,
        category: String = "GPG", 
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(level: .info, message: message, category: category, file: file, function: function, line: line)
    }
    
    public func warning(
        _ message: String,
        category: String = "GPG",
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(level: .warning, message: message, category: category, file: file, function: function, line: line)
    }
    
    public func error(
        _ message: String,
        category: String = "GPG",
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(level: .error, message: message, category: category, file: file, function: function, line: line)
    }
    
    public func critical(
        _ message: String,
        category: String = "GPG",
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(level: .critical, message: message, category: category, file: file, function: function, line: line)
    }
}

// MARK: - Convenience Extensions

extension GPGLogger {
    /// Log GPG command execution
    public func logCommand(_ command: [String], category: String = "Command") {
        debug("Executing GPG command: \(command.joined(separator: " "))", category: category)
    }
    
    /// Log GPG process result  
    public func logProcessResult(exitCode: Int32, stderr: String, category: String = "Process") {
        if exitCode == 0 {
            debug("GPG process completed successfully", category: category)
        } else {
            warning("GPG process exited with code \(exitCode): \(stderr)", category: category)
        }
    }
    
    /// Log status message parsing
    public func logStatusMessage(key: String, value: String, category: String = "Status") {
        debug("GPG status: \(key) = \(value)", category: category)
    }
    
    /// Log operation start/end
    public func logOperation<T>(_ operation: String, category: String = "Operation", block: () throws -> T) rethrows -> T {
        info("Starting \(operation)", category: category)
        let start = Date().timeIntervalSinceReferenceDate
        
        do {
            let result = try block()
            let duration = Date().timeIntervalSinceReferenceDate - start
            info("Completed \(operation) in \(String(format: "%.3f", duration))s", category: category)
            return result
        } catch {
            let duration = Date().timeIntervalSinceReferenceDate - start
            self.error("Failed \(operation) after \(String(format: "%.3f", duration))s: \(error)", category: category)
            throw error
        }
    }
    
    /// Log operation start/end (async version)
    public func logOperationAsync<T>(_ operation: String, category: String = "Operation", block: () async throws -> T) async rethrows -> T {
        info("Starting \(operation)", category: category)
        let start = Date().timeIntervalSinceReferenceDate
        
        do {
            let result = try await block()
            let duration = Date().timeIntervalSinceReferenceDate - start
            info("Completed \(operation) in \(String(format: "%.3f", duration))s", category: category)
            return result
        } catch {
            let duration = Date().timeIntervalSinceReferenceDate - start
            self.error("Failed \(operation) after \(String(format: "%.3f", duration))s: \(error)", category: category)
            throw error
        }
    }
}
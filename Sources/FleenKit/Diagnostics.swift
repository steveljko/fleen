import Foundation

/// Shared diagnostics log, written to a file.
///
/// A file rather than `NSLog`, because the two things worth diagnosing both happen
/// where console output is hard to retrieve: a sandboxed GUI app launched by
/// LaunchServices, and a short-lived extension process launched by Safari. One file
/// both can append to means a single place to look after something fails.
public enum Diagnostics {

    /// Enabled by a preference, so it survives a normal `open` launch, or by the
    /// environment for terminal runs.
    public static let isEnabled: Bool =
        ProcessInfo.processInfo.environment["FLEEN_DIAG"] == "1"
        || UserDefaults.standard.bool(forKey: "FleenDiagnostics")

    public static var fileURL: URL? {
        guard let library = FileManager.default.urls(for: .libraryDirectory,
                                                     in: .userDomainMask).first else { return nil }
        let directory = library.appendingPathComponent("Logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("Fleen-diagnostics.log")
    }

    public static func log(_ message: String, category: String = "") {
        guard isEnabled, let url = fileURL else { return }
        let stamp = Date().formatted(date: .numeric, time: .standard)
        let prefix = category.isEmpty ? "" : "[\(category)] "
        let line = "\(stamp)  \(prefix)\(message)\n"

        if let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: Data(line.utf8))
        } else {
            try? Data(line.utf8).write(to: url)
        }
    }
}

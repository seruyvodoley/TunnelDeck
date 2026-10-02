import Foundation

enum SecretRedactor {
    private static let patterns = [
        #"(?im)^\s*(PrivateKey|PresharedKey)\s*=\s*.*$"#,
        #"(?im)^\s*(private key|preshared key):\s*.*$"#,
        #"(?i)(Authorization\s*:\s*)([^\r\n]+)"#,
        #"(?i)(password\s*[=:]\s*)([^\s,;\r\n]+)"#,
        #"(?i)(token\s*[=:]\s*)([^\s,;\r\n]+)"#
        ,#"(?i)(Bearer\s+)([^\s,;\r\n]+)"#
        ,#"(?i)(Cookie\s*:\s*)([^\r\n]+)"#
        ,#"(?i)(uuid\s*[=:]\s*)([0-9a-f-]{20,})"#
    ]

    static func redact(_ input: String) -> String {
        patterns.reduce(input) { value, pattern in
            guard let expression = try? NSRegularExpression(pattern: pattern) else { return value }
            let range = NSRange(value.startIndex..., in: value)
            if pattern.contains("PrivateKey|PresharedKey") {
                return expression.stringByReplacingMatches(in: value, range: range, withTemplate: "$1 = [REDACTED]")
            }
            if pattern.contains("private key|preshared key") {
                return expression.stringByReplacingMatches(in: value, range: range, withTemplate: "$1: [REDACTED]")
            }
            return expression.stringByReplacingMatches(in: value, range: range, withTemplate: "$1[REDACTED]")
        }
    }
}

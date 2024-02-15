import Foundation

public extension Sequence where Element == String? {
    func compactJoined(separator: String = "") -> String {
        self.compactMap { $0 }.joined(separator: separator)
    }
}

public extension KeyValuePairs where Key == String, Value == String? {
    func compactJoined(separator: String = "") -> String {
        self.map { (key, value) in
            if let value {
                "\(key): \(value)"
            } else {
                nil
            }
        }
        .compactJoined(separator: separator)
    }
}

public extension KeyValuePairs where Key == String, Value == String {
    func joined(separator: String = "") -> String {
        self.map { (key, value) in
            "\(key): \(value)"
        }
        .joined(separator: separator)
    }
}


public extension String {
    func insertingLineBreaks(every n: Int) -> String {
        var result = ""
        
        self.enumerated().forEach { index, character in
            if index % n == 0 && index > 0 {
                result += "\n"
            }
            result.append(character)
        }
        
        return result
    }
}

import Foundation
import WolfBase

// http://www.dirk-loss.de/sshvis/drunken_bishop.pdf

public struct RandomArt: Identifiable {
    public let id = UUID()
    static let fieldSize = 8
    public static let width = fieldSize * 2 + 1 // 17
    public static let height = fieldSize + 1 // 9

    public let hash: SSHHash
    public let field: [Int]
    public let content: String

    public init(_ hash: SSHHash) {
        self.hash = hash
        let steps = Self.toBitPairs(hash.data)
        self.field = Self.walk(steps: steps)
        self.content = Self.parse(field: field)
    }
    
    public func contentWithBorder(topText: String = "", bottomText: String = "") -> String {
        Self.addBorders(content: content, topText: topText, bottomText: bottomText)
    }
    
    public enum Error: LocalizedError {
        case invalidMD5Fingerprint
        case invalidSHA256Fingerprint
    }
    
    public static let symbols: [Character] = {
        Array(" .o+=*BOX@%&#/^SE")
    }()
    
    static func numberOfPosition(x: Int, y: Int) -> Int {
        x + width * y
    }
    
    static let startPosition = numberOfPosition(x: width / 2, y: height / 2)
    
    static let positionTypeField: [Character] = {
        (0..<153).map { i in
            if i == 0 { "a" }
            else if i == 16 { "b" }
            else if i == 136 { "c" }
            else if i == 152 { "d" }
            else if (1...15).contains(i) { "T" }
            else if i % 17 == 0 { "L" }
            else if i % 17 == 16 { "R" }
            else if (137...151).contains(i) { "B" }
            else { "M" }
        }
    }()
    
    static func movement(bits: String, currentPosition: inout Int) {
        var ul = -18
        var ur = -16
        var dl = 16
        var dr = 18

        switch positionTypeField[currentPosition] {
        case "M":
            break
        case "T":
            ul = -1; ur = 1
        case "B":
            dl = -1; dr = 1
        case "L":
            ul = -17; dl = 17
        case "R":
            ur = -17; dr = 17
        case "a":
            ul = 0; ur = 1; dl = 17
        case "b":
            ul = -1; ur = 0; dr = 17
        case "c":
            ul = -17; dl = 0; dr = 1;
        case "d":
            ur = -17; dl = -1; dr = 0
        default:
            preconditionFailure()
        }

        switch bits {
            case "00":
                currentPosition += ul
            case "01":
                currentPosition += ur
            case "10":
                currentPosition += dl
            case "11":
                currentPosition += dr
            default:
                preconditionFailure()
        }
    }
    
    static func walk(steps: [String]) -> [Int] {
        var field = Array(repeating: 0, count: width * height)
        var currentPosition = startPosition
        
        for i in 0..<steps.count {
            let bits = steps[i]
            movement(bits: bits, currentPosition: &currentPosition)
            if field[currentPosition] < 14 {
                field[currentPosition] += 1
            }
        }
        field[startPosition] = 15
        field[currentPosition] = 16
        
        return field
    }
    
    static func parse(field: [Int]) -> String {
        var characters: [Character] = []
        
        for i in 0 ..< field.count {
            if i % 17 == 0 && i != 0 {
                characters += "\n"
            }
            
            let count = field[i]
            characters.append((0...16).contains(count) ? symbols[count] : "?")
        }
        
        return String(characters)
    }
    
    static func horizontalBorder(text: String = "") -> String {
        var s: [Character] = Array(repeating: "-", count: width + 2)
        s[0] = "+"
        s[18] = "+"
        
        if !text.isEmpty {
            let bracketedTitle = Array("[\(text)]")
            var x = (width - bracketedTitle.count) / 2 + 1
            for c in bracketedTitle {
                s[x] = c
                x += 1
            }
        }
        
        return String(s)
    }
    
    static func addBorders(content: String, topText: String, bottomText: String) -> String {
        var ra: [String] = [horizontalBorder(text: topText)]
        let lines = content.split(separator: "\n")
        for line in lines {
            ra.append("|\(line)|")
        }
        ra.append(horizontalBorder(text: bottomText))
        return ra.joined(separator: "\n")
    }

    static func toBitPairs(_ data: Data) -> [String] {
        var bitPairs: [String] = []

        for byte in data {
            let byteString = String(byte, radix: 2)
            let paddedByteString = String(repeating: "0", count: 8 - byteString.count) + byteString

            for j in 0..<4 {
                let pair = String(paddedByteString[paddedByteString.index(paddedByteString.startIndex, offsetBy: 6 - 2 * j)]) +
                           String(paddedByteString[paddedByteString.index(paddedByteString.startIndex, offsetBy: 7 - 2 * j)])
                bitPairs.append(pair)
            }
        }
        
        return bitPairs
    }
}

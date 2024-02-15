import Foundation

fileprivate let padding = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])

fileprivate let logRead = false
fileprivate let logWrite = false

struct SSHReadBuffer {
    var data: Data
    var index: UInt32 = 0

    enum Error: Swift.Error {
        case invalid
    }

    init(_ data: Data) {
        self.data = data
    }
    
    var isAtEnd: Bool {
        index == data.count
    }

    mutating func read(_ count: UInt32) throws -> Data {
        try check(index + count <= data.count)
        let bytes = data.subdata(in: Data.Index(index)..<Data.Index((index + count)))
        index += count
        if logRead {
            print("read: \(bytes.hex)")
        }
        return bytes
    }

    mutating func readInt() throws -> UInt32 {
        try check(index + 4 <= data.count)
        let lengthData = try read(4)
        return lengthData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    }

    mutating func readChunk() throws -> Data {
        let length = try readInt()
        return try read(length)
    }

    mutating func readChunks() throws -> [Data] {
        var chunks: [Data] = []
        while index < data.count {
            chunks.append(try readChunk())
        }
        return chunks
    }

    static func readChunks(from data: Data) throws -> [Data] {
        var buf = SSHReadBuffer(data)
        return try buf.readChunks()
    }

    mutating func readNullTerminatedString() throws -> String {
        var bytes = Data()
        while true {
            let byte = try read(1)
            if byte == Data([0]) {
                break
            }
            bytes.append(byte)
        }
        return String(data: bytes, encoding: .utf8)!
    }

    mutating func readLengthPrefixedString() throws -> String {
        let length = try readInt()
        let data = try read(length)
        guard let s = String(data: data, encoding: .utf8) else {
            throw Error.invalid
        }
        return s
    }

    mutating func expectPadding() throws {
        let paddingNeeded = 8 - (index % 8)
        let expectedPadding = padding.prefix(Int(paddingNeeded))
        let padding = try read(paddingNeeded)
        try check(padding == expectedPadding)
    }
}

fileprivate func check(_ pred: @autoclosure () -> Bool) throws {
    guard pred() else {
        throw SSHReadBuffer.Error.invalid
    }
}

struct SSHWriteBuffer {
    var data = Data()

    init() { }
    
    mutating func write(_ bytes: Data) {
        data.append(bytes)
        if logWrite {
            print("write: \(bytes.hex)")
        }
    }

    mutating func writeInt(_ n: UInt32) {
        var n = UInt32(n).bigEndian
        write(Data(bytes: &n, count: 4))
    }

    mutating func writeChunk(_ chunk: Data) {
        writeInt(UInt32(chunk.count))
        write(chunk)
    }
    
    mutating func writeEmptyChunk() {
        writeInt(0)
    }

    mutating func writeChunks(_ chunks: [Data]) {
        for chunk in chunks {
            writeChunk(chunk)
        }
    }

    static func writeChunks(_ chunks: [Data]) -> Data {
        var buf = SSHWriteBuffer()
        buf.writeChunks(chunks)
        return buf.data
    }

    mutating func writeNullTerminatedString(_ string: String) {
        write(string.data(using: .utf8)!)
        write(Data([0]))
    }

    mutating func writeLengthPrefixedString(_ string: String) {
        let stringData = string.data(using: .utf8)!
        writeInt(UInt32(stringData.count))
        write(stringData)
    }

    mutating func writePadding() {
        let paddingNeeded = 8 - (data.count % 8)
        write(padding.prefix(paddingNeeded))
    }
}

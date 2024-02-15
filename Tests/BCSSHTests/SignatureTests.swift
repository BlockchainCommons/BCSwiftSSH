import XCTest
import WolfBase
@testable import BCSSH

final class SignatureTests: XCTestCase {
    func testEd25519Signature1() throws {
        let sig = try SSHSignature(exampleMessageED25519Signature)
        XCTAssertEqual(sig.description, "SSHSignature(type: ssh-ed25519, hashAlgorithm: sha512, namespace: file, publicKeyData: 0f2954f7a55e51303fe401d241f7bcb31495411ce66a09dfd9ed626721facde0, data: 55206dfd5e7e8312f33cc52c8a0cc1c2be46fa0c2710f27ce784e59b5bc7a0412a231829fd6235419cd404d96856f8604353f36ef881cd3be3248e6b6d0ad001)")
        XCTAssertEqual(sig.string, exampleMessageED25519Signature)
    }
    
    func testEd25519Signature2() throws {
        let sig = try SSHSignature(exampleMessageED25519Signature)
        let publicKey = try SSHPublicKey(ed25519PublicKey)
        let isValid = try publicKey.verify(message: exampleMessage.utf8Data, signature: sig, namespace: sig.namespace)
        XCTAssertTrue(isValid)
    }
    
    func testEd25519Signature3() throws {
        let sig = try SSHSignature(exampleMessageED25519Signature)
        let privateKey = try SSHPrivateKey(ed25519PrivateKey)
        let publicKey = try SSHPublicKey(ed25519PublicKey)
        let sig2 = privateKey.sign(message: exampleMessage.utf8Data, namespace: sig.namespace)
        let isValid = try publicKey.verify(message: exampleMessage.utf8Data, signature: sig2, namespace: sig2.namespace)
        XCTAssertTrue(isValid)
    }
    
    func testEd25519Signature4() throws {
        let message = "You only live once. But if you do it right, once is enough. — Mae West\n"
        let messageData = message.utf8Data
        let namespace = "quote"
        let identity = "wolf@example.com"
        
        let privateKey = SSHPrivateKey(type: .ed25519, comment: identity)
        let signature = privateKey.sign(message: messageData, namespace: namespace)
        
        let publicKey = privateKey.publicKey
        let isValid = try publicKey.verify(message: messageData, signature: signature, namespace: namespace)
        XCTAssertTrue(isValid)
        
        #if os(macOS)
        // Make sure that `ssh-keygen` will actually verify the signature we just generated
        // by actually writing the necessary files to a temporary directory then executing
        // `ssh-keygen` on them.
        
        let filename = "Message.txt"
        let fileManager = FileManager.default
        let tempDir = fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        
        // The directory in which the temporary files will be created
        // print(tempDir.path)
        try fileManager.createDirectory(at: tempDir, withIntermediateDirectories: true)
        
        let messageFile = tempDir.appendingPathComponent(filename)
        let allowedSigners = tempDir.appendingPathComponent("allowed_signers")
        let signatureFile = tempDir.appendingPathComponent("\(filename).sig")
        
        try message.write(to: messageFile, atomically: true, encoding: .utf8)
        //try "incorrect".write(to: messageFile, atomically: true, encoding: .utf8)
        try publicKey.allowedSignerString(identity: identity).write(to: allowedSigners, atomically: true, encoding: .utf8)
        try signature.string.write(to: signatureFile, atomically: true, encoding: .utf8)
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = [
            "-Y", "verify",
            "-f", allowedSigners.path,
            "-I", identity,
            "-n", namespace,
            "-s", signatureFile.path
        ]
        process.standardInput = try FileHandle(forReadingFrom: messageFile)

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        // The command that will be executed
        // print(([process.executableURL!.path] + process.arguments!).joined(separator: " "))
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let output: String
            if let data = try pipe.fileHandleForReading.readToEnd() {
                output = String(decoding: data, as: UTF8.self)
            } else {
                output = "Unknown error"
            }
            XCTFail("Signature verification failed: \(output)")
        }

        try fileManager.removeItem(at: tempDir)
        #endif
    }
}

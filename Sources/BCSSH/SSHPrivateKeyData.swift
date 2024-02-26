import Foundation
import WolfBase
import BCCrypto

// https://coolaj86.com/articles/the-openssh-private-key-format/
// https://github.com/openssh/openssh-portable/blob/master/ssh-rsa.c

public enum SSHPrivateKeyData: Equatable, CustomStringConvertible {
    case rsa(modulus: Data, publicExponent: Data, privateExponent: Data, prime1: Data, prime2: Data, coefficient: Data)
    case dsa(Data)
    case ecdsa(type: ECDSAType, data: Data)
    case ed25519(privateKey: Data, publicKey: Data)
    
    init(type: SSHKeyType) {
        var rng = SecureRandomNumberGenerator()
        self.init(type: type, using: &rng)
    }
    
    init<R: RandomNumberGenerator>(type: SSHKeyType, using rng: inout R) {
        switch type {
        case .ed25519:
            let privateKey = ed25519NewPrivateKey(using: &rng)
            let publicKey = ed25519PublicKeyFromPrivateKey(privateKey: privateKey)
            self = .ed25519(privateKey: privateKey, publicKey: publicKey)
        default:
            unimplemented()
        }
    }
    
    init(buf: inout SSHReadBuffer, type: SSHKeyType) throws {
        let keyData: SSHPrivateKeyData
        switch type {
        case .rsa:
            let typeString = try buf.readLengthPrefixedString()
            guard typeString == type.description else {
                throw SSHPrivateKey.Error.invalid
            }
            let modulus = try buf.readChunk()
            let publicExponent = try buf.readChunk()
            let privateExponent = try buf.readChunk()
            let prime1 = try buf.readChunk()
            let prime2 = try buf.readChunk()
            let coefficient = try buf.readChunk()
            keyData = .rsa(modulus: modulus, publicExponent: publicExponent, privateExponent: privateExponent, prime1: prime1, prime2: prime2, coefficient: coefficient)
        case .dsa:
            let x = try buf.readChunk()
            keyData = .dsa(x)
        case .ecdsa(let ecdsaType):
            let typeString = try buf.readLengthPrefixedString()
            guard
                let internalType = ECDSAType(typeString),
                ecdsaType == internalType
            else {
                throw SSHPublicKey.Error.invalid
            }
            let data = try buf.readChunk()
            keyData = .ecdsa(type: ecdsaType, data: data)
        case .ed25519:
            let data = try buf.readChunk()
            guard data.count == 64 else {
                throw SSHPrivateKey.Error.invalid
            }
            let privateKey = data.subdata(in: 0..<32)
            let publicKey = data.subdata(in: 32..<64)
            keyData = .ed25519(privateKey: privateKey, publicKey: publicKey)
        }
        self = keyData
    }
    
    public var type: SSHKeyType {
        switch self {
        case .rsa(_, _, _, _, _, _):
                .rsa
        case .dsa(_):
                .dsa
        case .ecdsa(let type, _):
                .ecdsa(type)
        case .ed25519(_, _):
                .ed25519
        }
    }
    
    public var chunks: [Data] {
        switch self {
        case .rsa(let modulus, let publicExponent, let privateExponent, let prime1, let prime2, let coefficient):
            [modulus, publicExponent, privateExponent, prime1, prime2, coefficient]
        case .dsa(let x):
            [x]
        case .ecdsa(let type, let data):
            [type.description.utf8Data, data]
        case .ed25519(let privateKey, let publicKey):
            [privateKey + publicKey]
        }
    }
    
    public var description: String {
        switch self {
        case .rsa(let modulus, let publicExponent, let privateExponent, let prime1, let prime2, let coefficient):
            "(modulus: \(modulus.hex), publicExponent: \(publicExponent.hex), privateExponent: \(privateExponent.hex), prime1: \(prime1.hex), prime2: \(prime2.hex), coefficient: \(coefficient.hex))"
        case .dsa(let x):
            x.hex
        case .ecdsa(_, let data):
            data.hex
        case .ed25519(let privateKey, let publicKey):
            (privateKey + publicKey).hex
        }
    }
    
    public var publicKeyData: SSHPublicKeyData {
        switch self {
        case .ed25519(_, let publicKey):
            SSHPublicKeyData.ed25519(publicKey)
        default:
            unimplemented()
        }
    }
    
    public func derivePublicKeyData() -> SSHPublicKeyData {
        switch self {
        case .ed25519(let privateKey, _):
            SSHPublicKeyData.ed25519(ed25519PublicKeyFromPrivateKey(privateKey: privateKey))
        default:
            unimplemented()
        }
    }
}

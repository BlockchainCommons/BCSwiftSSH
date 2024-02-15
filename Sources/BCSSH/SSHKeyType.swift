import Foundation

public enum SSHKeyType: Equatable, CustomStringConvertible {
    case rsa
    case dsa
    case ecdsa(ECDSAType)
    case ed25519

    public init?(_ s: String) {
        switch s {
        case "ssh-rsa":
            self = .rsa
        case "ssh-dss":
            self = .dsa
        case "ecdsa-sha2-nistp256":
            self = .ecdsa(.nistp256)
        case "ecdsa-sha2-nistp384":
            self = .ecdsa(.nistp384)
        case "ecdsa-sha2-nistp521":
            self = .ecdsa(.nistp521)
        case "ssh-ed25519":
            self = .ed25519
        default:
            return nil
        }
    }

    public var description: String {
        switch self {
        case .rsa:
            return "ssh-rsa"
        case .dsa:
            return "ssh-dss"
        case .ecdsa(let type):
            return "ecdsa-sha2-\(type)"
        case .ed25519:
            return "ssh-ed25519"
        }
    }
    
    public var hashName: String {
        switch self {
        case .rsa:
            "RSA"
        case .dsa:
            "DSA"
        case .ecdsa:
            "ECDSA"
        case .ed25519:
            "ED25519"
        }
    }
}

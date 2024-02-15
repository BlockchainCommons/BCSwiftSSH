import Foundation

public enum ECDSAType: Equatable, CustomStringConvertible {
    case nistp256
    case nistp384
    case nistp521
    
    public init?(_ s: String) {
        switch s {
        case "nistp256":
            self = .nistp256
        case "nistp384":
            self = .nistp384
        case "nistp521":
            self = .nistp521
        default:
            return nil
        }
    }
    
    public var description: String {
        switch self {
        case .nistp256:
            "nistp256"
        case .nistp384:
            "nistp384"
        case .nistp521:
            "nistp521"
        }
    }
    
    public var keySize: Int {
        switch self {
        case .nistp256:
            256
        case .nistp384:
            384
        case .nistp521:
            521
        }
    }
}

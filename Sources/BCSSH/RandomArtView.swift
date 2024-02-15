#if canImport(SwiftUI)
import SwiftUI
import WolfBase

public struct RandomArtView: View {
    let randomArt: RandomArt
    @State var showTextView: Bool = false
    
    public init(randomArt: RandomArt) {
        self.randomArt = randomArt
    }
    
    public var body: some View {
        ZStack {
            RandomArtTextView(randomArt: randomArt)
            RandomArtGraphicView(randomArt: randomArt)
                .opacity(showTextView ? 0 : 1)
                .animation(.default, value: showTextView)
        }
        .onTapGesture {
            showTextView.toggle()
        }
    }
}

public struct RandomArtTextView: View {
    let randomArt: RandomArt
    
    public init(randomArt: RandomArt) {
        self.randomArt = randomArt
    }
    
    public var body: some View {
        Text(randomArt.content)
            .minimumScaleFactor(0.1)
            .font(.system(size: 100, weight: .regular, design: .monospaced))
            .padding(5)
            .border(Color.primary)
            .aspectRatio(1.0, contentMode: .fit)
    }
}

public struct RandomArtGraphicView: View {
    let randomArt: RandomArt
    
    public init(randomArt: RandomArt) {
        self.randomArt = randomArt
    }
    
    public var body: some View {
        Canvas { context, size in
            let hue = 0.66
            let padding = size.min * 0.02
            let background = Color(hue: hue, saturation: 1, brightness: 0.5)
            let colors: [Color?] = (0..<RandomArt.symbols.count).map {
                switch $0 {
                case 0:
                    return nil
                case 15:
                    return Color.green
                case 16:
                    return Color.red
                default:
                    let saturation = pow((1.0 .. 0.0).scale(Double($0) / Double(RandomArt.symbols.count)), 8)
                    return Color(hue: hue, saturation: saturation, brightness: 1)
                }
            }
            let gridSize = CGSize(width: size.width - 2 * padding, height: size.height - 2 * padding)
            let moduleSize = CGSize(width: gridSize.width / Double(RandomArt.width), height: gridSize.height / Double(RandomArt.height))
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(background))
            for pass in 1...2 {
                for row in 0 ..< RandomArt.height {
                    for col in 0 ..< RandomArt.width {
                        let cell = row * RandomArt.width + col
                        let field = randomArt.field[cell]
                        let isStartOrEnd = (15...16).contains(field)
                        if pass == 1 && isStartOrEnd {
                            continue
                        } else if pass == 2 && !isStartOrEnd {
                            continue
                        }
                        guard let color = colors[field] else { continue }
                        let moduleX = Double(col) * moduleSize.width + padding
                        let moduleY = Double(row) * moduleSize.height + padding
                        let origin = CGPoint(x: moduleX, y: moduleY)
                        
                        let minDimension = moduleSize.min
                        let xInset = minDimension * 0.06
                        let yInset = minDimension * 0.03
                        let path: Path
                        let rect = CGRect(origin: origin, size: moduleSize).insetBy(dx: xInset, dy: yInset)
                        switch field {
                        case 15, 16:
                            let r = CGRect(center: rect.center, size: CGSize(rect.size.min * 2))
                            path = Path(ellipseIn: r)
                        default:
                            let cornerRadius = minDimension * 0.3
                            path = Path(roundedRect: rect, cornerSize: CGSize(width: cornerRadius, height: cornerRadius))
                        }
                        context.fill(path, with: .color(color))
                    }
                }
            }
        }
        .aspectRatio(1.0, contentMode: .fit)
    }
}

extension CGSize {
    var min: Double {
        Swift.min(width, height)
    }
    
    init(_ n: Double) {
        self.init(width: n, height: n)
    }
}

extension CGRect {
    var center: CGPoint {
        CGPoint(x: minX + width / 2, y: minY + height / 2)
    }
    
    init(center: CGPoint, size: CGSize) {
        let origin = CGPoint(x: center.x - size.width / 2, y: center.y - size.height / 2)
        self.init(origin: origin, size: size)
    }
}

#if DEBUG
#Preview {
    ScrollView {
        VStack {
            Demo("42:6d:f8:5b:18:bf:f6:fd:4c:9f:6c:05:5f:de:44:2c", .md5)
            Demo("wjqs7Nq/4Yg/OVm0bZgera0u40GHzj3IargfNJOiOvA", .sha256)
            Demo(‡"c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", .sha256)
            Demo(‡"fc94b0c1e5b0987c5843997697ee9fb7", .md5)
            Demo(‡"731ee54c82233359e3d5e9f6ccf87e1f", .md5)
        }
    }
}

struct Demo: View {
    let randomArt: RandomArt
    
    init(_ data: Data, _ algorithm: SSHHash.Algorithm) {
        randomArt = try! RandomArt(SSHHash(data: data, algorithm: algorithm))
    }
    
    init(_ string: String, _ algorithm: SSHHash.Algorithm) {
        randomArt = try! RandomArt(SSHHash(string, algorithm: algorithm))
    }
    
    var body: some View {
        HStack {
            Spacer()
            RandomArtView(randomArt: randomArt)
                .frame(width: 200)
            Spacer()
        }
    }
}
#endif // DEBUG

#endif // canImport(SwiftUI)

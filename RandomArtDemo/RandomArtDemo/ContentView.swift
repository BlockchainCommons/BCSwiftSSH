import SwiftUI
import BCSSH
import WolfBase

struct ContentView: View {
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                ForEach(Self.modelItems) {
                    itemView($0)
                }
            }
        }
        .padding()
    }
    
    static let modelItems: [RandomArt] = {
        var result = [
            try! RandomArt(SSHHash("42:6d:f8:5b:18:bf:f6:fd:4c:9f:6c:05:5f:de:44:2c", algorithm: .md5)),
            try! RandomArt(SSHHash("wjqs7Nq/4Yg/OVm0bZgera0u40GHzj3IargfNJOiOvA", algorithm: .sha256)),
            try! RandomArt(SSHHash(data: ‡"c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", algorithm: .sha256)),
            try! RandomArt(SSHHash(data: ‡"fc94b0c1e5b0987c5843997697ee9fb7", algorithm: .md5)),
            try! RandomArt(SSHHash(data: ‡"731ee54c82233359e3d5e9f6ccf87e1f", algorithm: .md5)),
        ]
        for i in 0..<100 {
            result.append(randomModelItem())
        }
        return result
    }()
    
    static func randomModelItem() -> RandomArt {
        let count = Int.random(in: 16...64)
        let hashImage = Data((0..<count).map { _ in UInt8.random(in: 0...255) })
        return try! RandomArt(SSHHash(hashImage: hashImage))
    }
    
    @ViewBuilder
    func itemView(_ randomArt: RandomArt) -> some View {
        HStack {
            Spacer()
            VStack(spacing: 5) {
                HStack {
                    RandomArtView(randomArt: randomArt)
                        .frame(width: 120)
                }
                Text(randomArt.hash.string)
                    .monospaced()
                    .minimumScaleFactor(0.5)
                    .lineLimit(1)
            }
            Spacer()
        }
    }
}

#Preview {
    ContentView()
}

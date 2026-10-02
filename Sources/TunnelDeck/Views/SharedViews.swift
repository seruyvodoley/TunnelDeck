import SwiftUI

struct StatusDot: View {
    let state: HealthState
    var body: some View { Circle().fill(color).frame(width: 9, height: 9).shadow(color: color.opacity(0.4), radius: 3) }
    private var color: Color { switch state { case .online: .green; case .warning: .yellow; case .critical: .red; case .offline: .red; case .unknown: .gray } }
}

struct MetricCard<Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let content: Content
    var body: some View { VStack(alignment: .leading, spacing: 12) { Label(title, systemImage: icon).font(.headline); content.frame(maxWidth: .infinity, alignment: .leading) }.padding(16).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14)).overlay(RoundedRectangle(cornerRadius: 14).stroke(.quaternary)) }
}

struct KeyValueRow: View {
    let key: String; let value: String
    var body: some View { HStack { Text(key).foregroundStyle(.secondary); Spacer(); Text(value).lineLimit(1).textSelection(.enabled) } }
}

extension UInt64 {
    var byteString: String { ByteCountFormatter.string(fromByteCount: Int64(self), countStyle: .file) }
}
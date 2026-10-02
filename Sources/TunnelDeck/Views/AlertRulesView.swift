import SwiftUI

struct AlertRulesView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View { VStack(spacing: 0) {
        List {
            Section("Local per-node rules") {
                ForEach($model.alertRules) { $rule in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack { Toggle(rule.kind.rawValue, isOn: $rule.enabled); Spacer(); Text(rule.severity.rawValue.capitalized).foregroundStyle(.secondary); if model.alertStates[rule.id]?.active == true { Text(model.alertStates[rule.id]?.acknowledgedAt == nil ? "ACTIVE" : "ACKNOWLEDGED").foregroundStyle(.orange); Button("Acknowledge") { model.acknowledge(rule.id) } } }
                        if rule.threshold != nil { HStack { Text("Threshold").font(.caption); Slider(value: Binding(get: { rule.threshold ?? 0 }, set: { rule.threshold = $0 }), in: rule.kind == .ping ? 20...1000 : rule.kind == .peerInactive ? 60...86400 : 50...100, step: rule.kind == .ping ? 10 : 1); Text(String(format: "%.0f", rule.threshold ?? 0)).monospacedDigit().frame(width: 54) } }
                        Stepper("Cooldown: \(Int(rule.cooldown / 60)) min", value: $rule.cooldown, in: 0...86400, step: 60).font(.caption)
                    }.onChange(of: rule) { _, _ in model.saveAlertRules() }
                }
            }
            Section("Recent alert events") { ForEach(model.alertEvents.suffix(100).reversed()) { event in HStack { StatusDot(state: event.state); VStack(alignment: .leading) { Text(event.title); Text(event.timestamp.formatted()).font(.caption).foregroundStyle(.secondary) }; Spacer() } } }
        }
        Text("Rules are local and transition-only. Recovery creates a separate event.").font(.caption).foregroundStyle(.secondary).padding()
    } }
}

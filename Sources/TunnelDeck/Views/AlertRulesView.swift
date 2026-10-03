import SwiftUI

struct AlertRulesView: View {
    @EnvironmentObject var model: AppViewModel

    var body: some View {
        VStack(spacing: 0) {
            List {
                Section("Local per-node rules") {
                    ForEach($model.alertRules) { $rule in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Toggle(rule.kind.rawValue, isOn: $rule.enabled)
                                Spacer()
                                Text(rule.severity.rawValue.capitalized)
                                    .foregroundStyle(.secondary)
                                if model.alertStates[rule.id]?.active == true {
                                    Text(model.alertStates[rule.id]?.acknowledgedAt == nil ? "ACTIVE" : "ACKNOWLEDGED")
                                        .foregroundStyle(.orange)
                                    Button("Acknowledge") {
                                        model.acknowledge(rule.id)
                                    }
                                }
                            }

                            AlertThresholdEditor(rule: $rule)

                            Stepper(
                                "Cooldown: \(Int(rule.cooldown / 60)) min",
                                value: $rule.cooldown,
                                in: 0...86400,
                                step: 60
                            )
                            .font(.caption)
                        }
                        .onChange(of: rule) { _, _ in
                            model.saveAlertRules()
                        }
                    }
                }

                Section("Recent alert events") {
                    ForEach(model.alertEvents.suffix(100).reversed()) { event in
                        HStack {
                            StatusDot(state: event.state)
                            VStack(alignment: .leading) {
                                Text(event.title)
                                Text(event.timestamp.formatted())
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                    }
                }
            }

            Text("Rules are local and transition-only. Recovery creates a separate event.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding()
        }
    }
}

private struct AlertThresholdEditor: View {
    @Binding var rule: AlertRule

    var body: some View {
        if let configuration {
            Stepper(
                value: thresholdBinding(configuration),
                in: configuration.range,
                step: configuration.step
            ) {
                HStack {
                    Text("Threshold")
                    Spacer()
                    Text(displayValue(configuration))
                        .monospacedDigit()
                }
            }
            .font(.caption)
        }
    }

    private struct Configuration {
        let range: ClosedRange<Double>
        let step: Double
        let fallback: Double
        let suffix: String
    }

    private var configuration: Configuration? {
        switch rule.kind {
        case .disk, .memory:
            return Configuration(range: 50...100, step: 1, fallback: 90, suffix: "%")
        case .ping:
            return Configuration(range: 20...1000, step: 10, fallback: 250, suffix: " ms")
        case .peerInactive:
            return Configuration(range: 60...86400, step: 60, fallback: 180, suffix: " s")
        default:
            return nil
        }
    }

    private func thresholdBinding(_ configuration: Configuration) -> Binding<Double> {
        Binding(
            get: {
                clamped(rule.threshold ?? configuration.fallback, to: configuration.range)
            },
            set: { value in
                rule.threshold = clamped(value, to: configuration.range)
            }
        )
    }

    private func displayValue(_ configuration: Configuration) -> String {
        let value = clamped(rule.threshold ?? configuration.fallback, to: configuration.range)
        return "\(Int(value.rounded()))\(configuration.suffix)"
    }

    private func clamped(_ value: Double, to range: ClosedRange<Double>) -> Double {
        min(max(value, range.lowerBound), range.upperBound)
    }
}

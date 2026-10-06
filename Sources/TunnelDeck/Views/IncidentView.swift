import SwiftUI

struct IncidentView: View {
    @EnvironmentObject var model: AppViewModel

    var body: some View {
        let snapshot = IncidentEngine.metrics(model.incidents)

        ScrollView {
            LazyVStack(alignment: .leading, spacing: 16) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 170))]) {
                    tile("Active", model.incidents.lazy.filter { $0.recoveryState == .active }.count.description)
                    tile("Incidents · 24h", snapshot.day.description)
                    tile("Incidents · 7d", snapshot.week.description)
                    tile("VPS downtime · 24h", duration(snapshot.downtime))
                    tile("Mean recovery", snapshot.meanRecovery.map(duration) ?? "—")
                }

                ForEach(model.incidents.reversed()) { incident in
                    incidentCard(incident)
                }
            }
            .padding(20)
        }
    }

    private func incidentCard(_ incident: Incident) -> some View {
        let visibleTimeline = Array(incident.timeline.suffix(12))
        let hiddenCount = max(0, incident.timeline.count - visibleTimeline.count)

        return MetricCard(
            title: incident.observableCondition,
            icon: incident.recoveryState == .active ? "exclamationmark.triangle.fill" : "checkmark.circle"
        ) {
            VStack(alignment: .leading, spacing: 7) {
                KeyValueRow(key: "Start", value: incident.startedAt.formatted())
                KeyValueRow(key: "End", value: incident.endedAt?.formatted() ?? "Active")
                KeyValueRow(key: "Duration", value: duration(incident.duration))
                KeyValueRow(key: "Recovered", value: incident.recoveryState == .recovered ? "Yes" : "No")
                KeyValueRow(key: "Affected", value: incident.affectedComponents.joined(separator: ", "))
                Text("Observable condition — not asserted root cause")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if hiddenCount > 0 {
                    Text("\(hiddenCount) earlier timeline entries hidden")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                ForEach(visibleTimeline) { entry in
                    HStack {
                        StatusDot(state: entry.state)
                        Text(entry.timestamp.formatted(date: .omitted, time: .standard))
                            .monospacedDigit()
                        Text(entry.message)
                    }
                }
            }
        }
    }

    private func tile(_ title: String, _ value: String) -> some View {
        MetricCard(title: title, icon: "chart.bar") {
            Text(value)
                .font(.title2.bold())
                .monospacedDigit()
        }
    }

    private func duration(_ interval: TimeInterval) -> String {
        let seconds = max(0, Int(interval))
        return seconds >= 3600
            ? "\(seconds / 3600)h \((seconds % 3600) / 60)m"
            : "\(seconds / 60)m"
    }
}

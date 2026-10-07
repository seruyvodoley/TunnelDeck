import SwiftUI

struct ServerConsolePanel: View {
    @EnvironmentObject var model: AppViewModel

    @State private var command = ""
    @State private var transcript = ""
    @State private var isRunning = false
    @State private var unlocked = false

    @FocusState private var commandFocused: Bool

    var body: some View {
        MetricCard(title: "Server Console", icon: "terminal") {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Quick SSH Console")
                            .font(.headline)

                        Text("\(model.settings.username)@\(model.settings.host):\(model.settings.port)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }

                    Spacer()

                    if unlocked {
                        Label(
                            "Raw commands enabled",
                            systemImage: "exclamationmark.triangle.fill"
                        )
                        .font(.caption)
                        .foregroundStyle(.orange)
                    } else {
                        Label(
                            "Locked",
                            systemImage: "lock.fill"
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }

                if !unlocked {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(
                            "The console can execute arbitrary commands as the configured SSH user. " +
                            "It bypasses TunnelDeck's normal read-only command allow-list."
                        )
                        .foregroundStyle(.secondary)

                        Text(
                            "Console commands are not persisted to TunnelDeck logs or command history. " +
                            "Known passwords, tokens and WireGuard private keys are redacted from returned output."
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)

                        Button {
                            unlocked = true
                            transcript =
                                "TunnelDeck Quick Console\n" +
                                "Connected target: \(model.settings.username)@\(model.settings.host)\n" +
                                "Session history is memory-only.\n"
                            commandFocused = true
                        } label: {
                            Label(
                                "Enable Raw Console for This Session",
                                systemImage: "lock.open"
                            )
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        .regularMaterial,
                        in: RoundedRectangle(cornerRadius: 10)
                    )
                } else {
                    HStack(spacing: 8) {
                        quickButton("WG", command: "wg show")
                        quickButton("Sockets", command: "ss -tunap")
                        quickButton("Conntrack", command: "conntrack -L | head -n 100")
                        quickButton("Firewall", command: "nft list ruleset")
                        quickButton(
                            "Services",
                            command: "systemctl --no-pager --failed"
                        )

                        Spacer()

                        Button("Clear") {
                            transcript = ""
                        }
                    }

                    ScrollView {
                        Text(
                            transcript.isEmpty
                                ? "Console output will appear here."
                                : transcript
                        )
                        .font(.system(size: 12, design: .monospaced))
                        .frame(
                            maxWidth: .infinity,
                            alignment: .topLeading
                        )
                        .textSelection(.enabled)
                        .padding(10)
                    }
                    .frame(minHeight: 220, idealHeight: 300, maxHeight: 420)
                    .background(
                        Color(nsColor: .textBackgroundColor),
                        in: RoundedRectangle(cornerRadius: 8)
                    )
                    .overlay {
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(.separator.opacity(0.6))
                    }

                    HStack(spacing: 8) {
                        Text(prompt)
                            .font(.system(.body, design: .monospaced))
                            .foregroundStyle(.secondary)

                        TextField(
                            "command",
                            text: $command
                        )
                        .font(.system(.body, design: .monospaced))
                        .textFieldStyle(.roundedBorder)
                        .focused($commandFocused)
                        .onSubmit {
                            run()
                        }
                        .disabled(isRunning)

                        Button {
                            run()
                        } label: {
                            if isRunning {
                                ProgressView()
                                    .controlSize(.small)
                                    .frame(width: 18, height: 18)
                            } else {
                                Label("Run", systemImage: "play.fill")
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(
                            isRunning ||
                            command.trimmingCharacters(
                                in: .whitespacesAndNewlines
                            ).isEmpty
                        )
                    }

                    Text(
                        "Quick Console is non-interactive: apt, systemctl, wg, ss, " +
                        "conntrack, journalctl and shell pipelines work. " +
                        "Interactive programs such as nano, htop and installers " +
                        "that require a real TTY need the future Full PTY Terminal."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var prompt: String {
        "\(model.settings.username)@server $"
    }

    @ViewBuilder
    private func quickButton(
        _ title: String,
        command preset: String
    ) -> some View {
        Button(title) {
            command = preset
            commandFocused = true
        }
        .disabled(isRunning)
    }

    private func run() {
        guard unlocked, !isRunning else { return }

        let value = command.trimmingCharacters(
            in: .whitespacesAndNewlines
        )

        guard !value.isEmpty else { return }

        let displayCommand = SecretRedactor.redact(value)
        let configuration = model.configuration
        let ssh = model.ssh

        command = ""
        isRunning = true

        if !transcript.isEmpty, !transcript.hasSuffix("\n") {
            transcript += "\n"
        }

        transcript += "\n\(prompt) \(displayCommand)\n"

        Task { @MainActor in
            do {
                let result = try await ssh.executeConsole(
                    value,
                    configuration: configuration
                )

                if !result.stdout.isEmpty {
                    transcript += result.stdout
                    if !result.stdout.hasSuffix("\n") {
                        transcript += "\n"
                    }
                }

                if !result.stderr.isEmpty {
                    transcript += "[stderr]\n\(result.stderr)"
                    if !result.stderr.hasSuffix("\n") {
                        transcript += "\n"
                    }
                }

                if result.exitCode != 0 {
                    transcript += "[exit \(result.exitCode)]\n"
                }
            } catch {
                transcript +=
                    "[TunnelDeck error] " +
                    SecretRedactor.redact(error.localizedDescription) +
                    "\n"
            }

            isRunning = false
            commandFocused = true
        }
    }
}

import SwiftUI
import KdbxCore

/// The live one-time code for an entry: the current digits, a countdown ring, and a
/// copy button.
///
/// The code is treated as a secret like any password — copied through
/// `ClipboardService.copySecret`, so it is concealed from clipboard managers and
/// auto-cleared. It is short-lived anyway, but it is still an authentication factor.
struct TOTPView: View {
    let totp: TOTP
    let onCopy: (String) -> Void

    /// Ticks the display. One second is enough: the ring is a countdown, not an
    /// animation, and a faster timer would burn power for no visible gain.
    @State private var now = Date()
    private let tick = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var code: String { totp.code(at: now) }
    private var remaining: Int { totp.secondsRemaining(at: now) }

    /// Red in the last five seconds, so a code about to expire is obvious before you
    /// paste it somewhere and have it rejected.
    private var isExpiringSoon: Bool { remaining <= 5 }

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 1) {
                Text("One-time code")
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)

                Text(TOTP.formatted(code))
                    .font(.title3.monospacedDigit().weight(.medium))
                    .contentTransition(.numericText())
                    .textSelection(.enabled)
                    .foregroundStyle(isExpiringSoon ? Design.Palette.danger
                                                    : Design.Palette.primaryText)
            }

            Spacer()

            countdown

            Button {
                onCopy(code)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy one-time code")
            .accessibilityLabel("Copy one-time code")
        }
        .padding(.vertical, Design.Metrics.rowVerticalPadding - 3)
        .onReceive(tick) { now = $0 }
        .onAppear { now = Date() }
        .accessibilityElement(children: .combine)
        // Spoken with the digits spaced out, so VoiceOver reads "1 2 3 4 5 6" rather
        // than "one hundred twenty-three thousand…".
        .accessibilityLabel("One-time code \(code.map(String.init).joined(separator: " ")), \(remaining) seconds remaining")
    }

    private var countdown: some View {
        ZStack {
            Circle()
                .stroke(Design.Palette.separator, lineWidth: 2)
            Circle()
                .trim(from: 0, to: 1 - totp.progress(at: now))
                .stroke(isExpiringSoon ? Design.Palette.danger : Design.Palette.accent,
                        style: StrokeStyle(lineWidth: 2, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(Design.animation(.linear(duration: 1)), value: remaining)

            Text("\(remaining)")
                .font(.system(size: 9, weight: .semibold).monospacedDigit())
                .foregroundStyle(Design.Palette.secondaryText)
        }
        .frame(width: 24, height: 24)
        .accessibilityHidden(true)
    }
}

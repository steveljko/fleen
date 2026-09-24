import SwiftUI

/// Shared visual language.
///
/// The brief was "feel like a first-party Apple app" without cloning one. That means
/// leaning on system materials, semantic colours and SF Symbols rather than inventing
/// a palette — an app that hardcodes its greys is the one that looks wrong the moment
/// the user switches appearance or increases contrast.
enum Design {

    enum Metrics {
        static let popoverWidth: CGFloat = 380
        /// The popover's height, in every state. Deliberately one constant rather than
        /// a range: sizing to content meant the window changed height on each
        /// navigation — entering a folder, searching, opening an entry — which is
        /// distracting and moves the controls out from under the pointer.
        static let popoverHeight: CGFloat = 460
        /// Estimated height of one folder or entry row, used to size the list to its
        /// contents. Rows are icon + two lines of text plus padding.
        static let estimatedRowHeight: CGFloat = 40

        /// One height for every control sitting in a bar, so the search field and the
        /// actions button are the same size and share a baseline.
        static let controlHeight: CGFloat = 28
        /// The actions button beside the search field. Square-ish, so it reads as one
        /// control rather than a second field.
        static let actionsButtonWidth: CGFloat = 32

        /// Breadcrumbs sit just under control height — secondary navigation, but still
        /// a comfortable target.
        static let crumbHeight: CGFloat = 26
        /// Widest a single breadcrumb may be before its name truncates.
        static let crumbMaxWidth: CGFloat = 140

        static let cornerRadius: CGFloat = 8
        static let controlCornerRadius: CGFloat = 6
        /// Large inputs that carry a screen, like the master password field.
        static let fieldCornerRadius: CGFloat = 10
        /// Height of such a field. Set explicitly rather than derived from padding:
        /// padding stacks on top of the font's own line height, so a larger font
        /// produced a cramped, off-centre line.
        static let largeFieldHeight: CGFloat = 44
        /// Margin for full-window states (the lock screen, empty states).
        static let screenPadding: CGFloat = 28

        /// Horizontal inset shared by every bar and list, so nothing looks inset by
        /// a slightly different amount than the thing above it.
        static let gutter: CGFloat = 10
        static let barVerticalPadding: CGFloat = 8
        static let rowVerticalPadding: CGFloat = 5

        static let spacing: CGFloat = 12
        static let tightSpacing: CGFloat = 6
    }

    /// Semantic colours only — these follow light/dark and increase-contrast for free.
    enum Palette {
        static let primaryText = Color.primary
        static let secondaryText = Color.secondary
        static let accent = Color.accentColor
        static let danger = Color(nsColor: .systemRed)
        static let warning = Color(nsColor: .systemOrange)
        static let success = Color(nsColor: .systemGreen)
        static let separator = Color(nsColor: .separatorColor)
    }

    /// Animation that disappears entirely under Reduce Motion, rather than merely
    /// running faster — the accessibility setting asks for no motion, not less.
    static func animation(_ base: Animation = .easeOut(duration: 0.18)) -> Animation? {
        NSWorkspace.shared.accessibilityDisplayShouldReduceMotion ? nil : base
    }
}

/// A hover highlight for anything clickable.
///
/// Rows and breadcrumbs are navigation targets, but without feedback they read as
/// static text — there is nothing to tell you a folder can be opened until you have
/// already clicked it. The fill is deliberately faint: it marks what is under the
/// pointer without competing with the selection highlight.
struct HoverHighlight: ViewModifier {
    var cornerRadius: CGFloat = Design.Metrics.cornerRadius
    var inset: CGFloat = 0
    /// Changing this clears the highlight.
    ///
    /// Needed because SwiftUI reuses row views when a list's contents change. Open a
    /// folder and the view under the pointer is recycled into the new listing without
    /// ever receiving `onHover(false)` — so the highlight sticks to whatever row now
    /// occupies that position, and nothing the user does clears it. Resetting on
    /// navigation is the reliable fix; the highlight returns the moment the pointer
    /// actually moves.
    var resetToken: AnyHashable = 0

    @State private var isHovered = false

    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(isHovered ? Color.primary.opacity(0.07) : .clear)
                    .padding(-inset)
            )
            .contentShape(Rectangle())
            .onHover { hovering in
                withAnimation(Design.animation(.easeOut(duration: 0.12))) {
                    isHovered = hovering
                }
            }
            .onChange(of: resetToken) { _, _ in
                // No animation: fading out a highlight the user has already navigated
                // away from just draws attention to the wrong row.
                isHovered = false
            }
    }
}

extension View {
    func hoverHighlight(cornerRadius: CGFloat = Design.Metrics.cornerRadius,
                        inset: CGFloat = 0,
                        resetToken: AnyHashable = 0) -> some View {
        modifier(HoverHighlight(cornerRadius: cornerRadius, inset: inset,
                                resetToken: resetToken))
    }

    func selectableRow(isSelected: Bool, resetToken: AnyHashable = 0) -> some View {
        modifier(SelectableRow(isSelected: isSelected, resetToken: resetToken))
    }
}

/// Selection and hover drawn as one inset, rounded fill.
///
/// Replaces `List`'s built-in selection, which paints a hard edge-to-edge system-blue
/// bar — far too loud for a popover, and impossible to reconcile with the softer hover
/// treatment next to it. Doing both here also means the two states can never
/// double-draw on the same row.
struct SelectableRow: ViewModifier {
    let isSelected: Bool
    var resetToken: AnyHashable = 0

    @State private var isHovered = false

    private var fill: Color {
        if isSelected { return Color.accentColor.opacity(0.16) }
        if isHovered { return Color.primary.opacity(0.07) }
        return .clear
    }

    func body(content: Content) -> some View {
        content
            .padding(.horizontal, Design.Metrics.tightSpacing)
            .background(
                RoundedRectangle(cornerRadius: Design.Metrics.cornerRadius, style: .continuous)
                    .fill(fill)
            )
            .contentShape(Rectangle())
            .onHover { hovering in
                withAnimation(Design.animation(.easeOut(duration: 0.12))) {
                    isHovered = hovering
                }
            }
            // See HoverHighlight: recycled rows never get onHover(false), so the
            // highlight has to be cleared explicitly when the list changes.
            .onChange(of: resetToken) { _, _ in isHovered = false }
    }
}

/// A transient message shown over the content instead of in a permanent bar.
///
/// Replaces the old always-visible status footer: "copied" and the clipboard
/// countdown are the only things worth surfacing, and both are momentary, so they
/// should not cost a strip of the window the whole time the vault is open.
struct ToastView: View {
    let text: String
    var symbol: String = "checkmark.circle.fill"
    var tint: Color = Design.Palette.success

    var body: some View {
        Label(text, systemImage: symbol)
            .font(.caption.weight(.medium))
            .foregroundStyle(tint)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(
                Capsule().fill(.regularMaterial)
            )
            .overlay(
                Capsule().strokeBorder(Design.Palette.separator, lineWidth: 0.5)
            )
            .shadow(color: .black.opacity(0.12), radius: 6, y: 2)
            .padding(.bottom, 12)
            .transition(.opacity.combined(with: .move(edge: .bottom)))
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isStaticText)
    }
}

/// The designed empty/error state. PLAN.md calls out that these must be designed
/// rather than left as default SwiftUI placeholders, so every "nothing here" path in
/// the app routes through this one view.
struct StatusMessageView: View {
    enum Kind {
        case neutral, warning, error

        var symbol: String {
            switch self {
            case .neutral: return "magnifyingglass"
            case .warning: return "exclamationmark.triangle.fill"
            case .error: return "xmark.octagon.fill"
            }
        }

        var tint: Color {
            switch self {
            case .neutral: return Design.Palette.secondaryText
            case .warning: return Design.Palette.warning
            case .error: return Design.Palette.danger
            }
        }
    }

    var kind: Kind = .neutral
    var symbol: String?
    let title: String
    var message: String?
    var actionTitle: String?
    var action: (() -> Void)?

    var body: some View {
        VStack(spacing: Design.Metrics.tightSpacing) {
            Image(systemName: symbol ?? kind.symbol)
                .font(.system(size: 26, weight: .regular))
                .foregroundStyle(kind.tint)
                .accessibilityHidden(true)

            Text(title)
                .font(.headline)
                .multilineTextAlignment(.center)

            if let message {
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(Design.Palette.secondaryText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.link)
                    .padding(.top, 2)
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // One combined element, so VoiceOver reads the state as a sentence rather
        // than announcing an icon and three unrelated labels.
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title). \(message ?? "")")
    }
}

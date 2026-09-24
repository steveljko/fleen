import SwiftUI
import FleenKit
import KdbxCore

/// One entry in full: fields, custom fields, attachments.
///
/// Protected values stay masked until explicitly revealed, and revealing is a
/// deliberate per-field action rather than a global toggle — so a shoulder-surfer
/// sees at most the one field the user meant to show.
struct EntryDetailView: View {
    let entry: Entry
    let database: Database?
    let preferences: Preferences
    let onCopied: (String) -> Void

    @State private var revealed: Set<String> = []

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Design.Metrics.spacing) {
                    if entry.times.isExpired { expiredBanner }
                    if hasAnyStandardField { standardFields }
                    if !displayableCustomFields.isEmpty { customFields }
                    if !resolvedAttachments.isEmpty { attachments }
                    if hasMetadata { metadata }
                    if isEmptyEntry { emptyState }
                }
                .padding(Design.Metrics.spacing)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onDisappear { revealed.removeAll() }
    }

    /// Custom fields worth showing.
    ///
    /// Excludes the keys that exist only to *store* TOTP configuration — they are
    /// already presented as a live code above, and showing the raw seed next to it is
    /// both redundant and a second place for the secret to be read from. Empty values
    /// are dropped too: a labelled row with nothing in it is just noise.
    private var displayableCustomFields: [(name: String, value: FieldValue)] {
        entry.meaningfulCustomFields
            .map { (name: $0.key, value: $0.value) }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// Attachments whose bytes are actually in the pool. A reference that does not
    /// resolve would render a row with a Save button that silently does nothing.
    private var resolvedAttachments: [AttachmentRef] {
        entry.attachments.filter { database?.attachment(for: $0) != nil }
    }

    private var hasAnyStandardField: Bool {
        !entry.username.isEmpty
            || !(entry.password?.isEmpty ?? true)
            || !entry.url.isEmpty
            || !entry.notes.isEmpty
            || !entry.tags.isEmpty
            || entry.totp != nil
    }

    private var hasMetadata: Bool {
        entry.times.creationTime != nil
            || entry.times.lastModificationTime != nil
            || (entry.times.expires && entry.times.expiryTime != nil)
    }

    /// An entry carrying nothing but a title. Rare, but it would otherwise render a
    /// completely blank pane that looks like a failure to load.
    private var isEmptyEntry: Bool {
        !hasAnyStandardField && displayableCustomFields.isEmpty
            && resolvedAttachments.isEmpty && !hasMetadata
    }

    private var emptyState: some View {
        StatusMessageView(
            symbol: "tray",
            title: "Nothing stored here",
            message: "This entry has a title but no username, password or other fields.")
            .frame(maxWidth: .infinity)
    }

    private var expiredBanner: some View {
        Label("This entry has expired", systemImage: "exclamationmark.circle.fill")
            .font(.caption)
            .foregroundStyle(Design.Palette.warning)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Design.Metrics.gutter)
            .padding(.vertical, Design.Metrics.tightSpacing)
            .background(
                RoundedRectangle(cornerRadius: Design.Metrics.controlCornerRadius,
                                 style: .continuous)
                    .fill(Design.Palette.warning.opacity(0.12)))
            .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var standardFields: some View {
        VStack(spacing: Design.Metrics.tightSpacing) {
            if !entry.username.isEmpty {
                FieldRow(label: "Username", value: .plain(entry.username),
                         isRevealed: true,
                         onCopy: { copy(entry.username, label: "Username", secret: false) },
                         onToggleReveal: nil)
            }
            if let password = entry.password, !password.isEmpty {
                FieldRow(label: "Password", value: password,
                         isRevealed: revealed.contains(Entry.passwordField),
                         onCopy: { copy(password.reveal(), label: "Password", secret: true) },
                         onToggleReveal: { toggle(Entry.passwordField) })
            }
            if !entry.url.isEmpty {
                FieldRow(label: "Address", value: .plain(entry.url),
                         isRevealed: true,
                         onCopy: { copy(entry.url, label: "Address", secret: false) },
                         onToggleReveal: nil,
                         onOpen: openURL)
            }
            if let totp = entry.totp {
                // A live generated code, not the stored URI: the URI is only useful
                // for moving the secret elsewhere, while the code is what you came for.
                TOTPView(totp: totp) { code in
                    copy(code, label: "One-time code", secret: true)
                }
            }
            if !entry.notes.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Notes").font(.caption).foregroundStyle(Design.Palette.secondaryText)
                    Text(entry.notes)
                        .font(.callout)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            if !entry.tags.isEmpty {
                HStack {
                    Text("Tags").font(.caption).foregroundStyle(Design.Palette.secondaryText)
                    Text(entry.tags.joined(separator: ", ")).font(.callout)
                    Spacer()
                }
            }
        }
    }

    private var customFields: some View {
        VStack(alignment: .leading, spacing: Design.Metrics.tightSpacing) {
            Text("Custom fields")
                .font(.caption.weight(.semibold))
                .foregroundStyle(Design.Palette.secondaryText)
            ForEach(displayableCustomFields, id: \.name) { field in
                FieldRow(label: field.name, value: field.value,
                         isRevealed: !field.value.isProtected || revealed.contains(field.name),
                         onCopy: {
                             copy(field.value.reveal(), label: field.name,
                                  secret: field.value.isProtected)
                         },
                         onToggleReveal: field.value.isProtected ? { toggle(field.name) } : nil)
            }
        }
    }

    private var attachments: some View {
        VStack(alignment: .leading, spacing: Design.Metrics.tightSpacing) {
            Text("Attachments")
                .font(.caption.weight(.semibold))
                .foregroundStyle(Design.Palette.secondaryText)
            ForEach(resolvedAttachments, id: \.name) { ref in
                HStack {
                    Image(systemName: "paperclip").foregroundStyle(Design.Palette.secondaryText)
                    Text(ref.name).font(.callout).lineLimit(1)
                    Spacer()
                    if let size = database?.attachment(for: ref)?.data.count {
                        Text(ByteCountFormatter.string(fromByteCount: Int64(size),
                                                       countStyle: .file))
                            .font(.caption2)
                            .foregroundStyle(Design.Palette.secondaryText)
                    }
                    Button("Save…") { export(ref) }
                        .buttonStyle(.link)
                        .font(.caption)
                }
                .accessibilityElement(children: .combine)
            }
        }
    }

    private var metadata: some View {
        VStack(alignment: .leading, spacing: 2) {
            if let created = entry.times.creationTime {
                Text("Created \(created.formatted(date: .abbreviated, time: .shortened))")
            }
            if let modified = entry.times.lastModificationTime {
                Text("Modified \(modified.formatted(date: .abbreviated, time: .shortened))")
            }
            if entry.times.expires, let expiry = entry.times.expiryTime {
                Text("Expires \(expiry.formatted(date: .abbreviated, time: .shortened))")
            }
        }
        .font(.caption2)
        .foregroundStyle(Design.Palette.secondaryText)
    }

    // MARK: Actions

    private func toggle(_ key: String) {
        withAnimation(Design.animation()) {
            if revealed.contains(key) { revealed.remove(key) } else { revealed.insert(key) }
        }
    }

    private func copy(_ value: String, label: String, secret: Bool) {
        if secret {
            ClipboardService.shared.copySecret(value, clearAfter: preferences.clipboardClearSeconds)
        } else {
            ClipboardService.shared.copyPlain(value)
        }
        onCopied("\(label) copied")
    }

    private func openURL() {
        guard let url = URL(string: entry.url), url.scheme != nil else { return }
        NSWorkspace.shared.open(url)
    }

    /// Writes an attachment out to a location the user picks.
    ///
    /// Deliberately an explicit save rather than a temp-file Quick Look preview: a
    /// preview would drop a decrypted copy of a potentially sensitive attachment into
    /// a temporary directory that nothing in this app controls the lifetime of.
    private func export(_ ref: AttachmentRef) {
        guard let attachment = database?.attachment(for: ref) else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = ref.name
        panel.message = "Save “\(ref.name)” from \(entry.title)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try attachment.data.write(to: url, options: [.atomic])
        } catch {
            NSAlert(error: error).runModal()
        }
    }
}

/// `textSelection` returns different concrete types for enabled and disabled, so a
/// ternary cannot pick between them; this picks a branch instead.
struct ConditionalTextSelection: ViewModifier {
    let enabled: Bool

    func body(content: Content) -> some View {
        if enabled {
            content.textSelection(.enabled)
        } else {
            content.textSelection(.disabled)
        }
    }
}

/// A labelled field with copy and reveal affordances.
struct FieldRow: View {
    let label: String
    let value: FieldValue
    let isRevealed: Bool
    var revealedOverride: String?
    let onCopy: () -> Void
    let onToggleReveal: (() -> Void)?
    var onOpen: (() -> Void)?

    private var shown: String {
        if let revealedOverride { return revealedOverride }
        guard isRevealed else { return String(repeating: "•", count: 10) }
        return value.reveal()
    }

    var body: some View {
        HStack(spacing: Design.Metrics.tightSpacing) {
            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)
                Text(shown)
                    .font(.callout.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                    // Selection is only enabled while revealed — a concealed field
                    // must not be selectable and copyable as a row of bullets.
                    .modifier(ConditionalTextSelection(enabled: isRevealed))
            }
            Spacer()

            if let onOpen {
                Button(action: onOpen) { Image(systemName: "arrow.up.forward.app") }
                    .buttonStyle(.borderless)
                    .help("Open in browser")
                    .accessibilityLabel("Open \(label) in browser")
            }
            if let onToggleReveal {
                Button(action: onToggleReveal) {
                    Image(systemName: isRevealed ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .help(isRevealed ? "Hide" : "Reveal")
                .accessibilityLabel(isRevealed ? "Hide \(label)" : "Reveal \(label)")
            }
            Button(action: onCopy) { Image(systemName: "doc.on.doc") }
                .buttonStyle(.borderless)
                .help("Copy \(label)")
                .accessibilityLabel("Copy \(label)")
        }
        .padding(.vertical, Design.Metrics.rowVerticalPadding - 3)
        // Never speak a concealed value; announce its presence instead.
        .accessibilityElement(children: .contain)
    }
}

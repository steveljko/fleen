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
    @State private var historyExpanded = false

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Design.Metrics.spacing) {
                    if entry.times.isExpired { expiredBanner }
                    if hasAnyStandardField { standardFields }
                    if !displayableCustomFields.isEmpty { customFields }
                    if !resolvedAttachments.isEmpty { attachments }
                    if !entry.history.isEmpty { history }
                    if hasMetadata { metadata }
                    if isEmptyEntry { emptyState }
                }
                .padding(Design.Metrics.spacing)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onDisappear { revealed.removeAll(); historyExpanded = false }
        // A revealed value is readable by anything watching the screen or the
        // accessibility tree, so it does not stay revealed for longer than it takes to
        // read. Restarts whenever another field is revealed.
        .task(id: revealed) {
            guard !revealed.isEmpty else { return }
            try? await Task.sleep(for: .seconds(Self.revealDuration))
            guard !Task.isCancelled else { return }
            withAnimation(Design.animation()) { revealed.removeAll() }
        }
    }

    static let revealDuration = 30

    /// Every field the user put on the entry, including ones left empty.
    ///
    /// Name order in general, but a card is listed the way it is read — number, expiry,
    /// security code, PIN — rather than alphabetically, which would put CVV above the
    /// number. The TOTP keys are the one omission: the live code is shown above, and the
    /// URI and seed that produce it are ingredients rather than content.
    private var displayableCustomFields: [(name: String, value: FieldValue)] {
        entry.orderedCustomFields()
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
            ForEach(displayableCustomFields, id: \.name) { field in
                if let card = CardNumber.detect(label: field.name, value: field.value) {
                    // A card number is treated as secret whether or not the database
                    // marked it protected, and hides as **** **** **** 1234 rather than
                    // an undifferentiated run of dots.
                    FieldRow(label: field.name, value: field.value,
                             isRevealed: revealed.contains(field.name),
                             revealedOverride: revealed.contains(field.name)
                                 ? card.grouped : nil,
                             maskedOverride: card.masked,
                             onCopy: {
                                 // Bare digits: a payment form rejects the spaces.
                                 copy(card.digits, label: field.name, secret: true)
                             },
                             onToggleReveal: { toggle(field.name) })
                } else {
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

    /// Previous versions of this entry, as KeePassXC recorded them.
    ///
    /// The data was already parsed and then thrown away — nothing read `Entry.history`.
    /// It answers the question a read-only companion should be able to answer: what was
    /// this password before I rotated it, and when did it change? Collapsed by default,
    /// because it is a reference, not part of reading the entry.
    private var history: some View {
        DisclosureGroup(isExpanded: $historyExpanded) {
            VStack(alignment: .leading, spacing: Design.Metrics.tightSpacing) {
                ForEach(Array(sortedHistory.enumerated()), id: \.offset) { index, version in
                    historyRow(version, index: index)
                }
            }
            .padding(.top, Design.Metrics.tightSpacing)
        } label: {
            Text("Previous versions (\(entry.history.count))")
                .font(.caption.weight(.semibold))
                .foregroundStyle(Design.Palette.secondaryText)
        }
    }

    /// Newest first: the most recent previous value is the one someone is looking for.
    private var sortedHistory: [Entry] {
        entry.history.sorted {
            ($0.times.lastModificationTime ?? .distantPast)
                > ($1.times.lastModificationTime ?? .distantPast)
        }
    }

    @ViewBuilder
    private func historyRow(_ version: Entry, index: Int) -> some View {
        let key = "__history.\(index)"
        VStack(alignment: .leading, spacing: 2) {
            Text(version.times.lastModificationTime
                 .map { $0.formatted(date: .abbreviated, time: .shortened) }
                 ?? "Undated version")
                .font(.caption)
                .foregroundStyle(Design.Palette.secondaryText)

            if let password = version.password, !password.isEmpty {
                FieldRow(label: "Password", value: password,
                         isRevealed: revealed.contains(key),
                         onCopy: { copy(password.reveal(), label: "Previous password",
                                        secret: true) },
                         onToggleReveal: { toggle(key) })
            }
            if !version.username.isEmpty, version.username != entry.username {
                // Only when it differs: repeating the current username on every row is
                // noise, and the point of this list is what changed.
                Text("Username was \(version.username)")
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)
            }
        }
        .padding(.vertical, 2)
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
        // Web addresses only. The URL comes from the database, which may be shared or
        // tampered with, and `NSWorkspace.open` will just as happily launch a `file://`
        // app, mount an `smb://` share or fire another app's URL handler — none of
        // which is what a button labelled "Open in browser" should do.
        guard let url = URL(string: entry.url),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme) else { NSSound.beep(); return }
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
    /// What to show while hidden, for values with a meaningful masked form of their own
    /// — a card number reads as `**** **** **** 1234` rather than a fixed run of dots.
    var maskedOverride: String?
    let onCopy: () -> Void
    let onToggleReveal: (() -> Void)?
    var onOpen: (() -> Void)?

    private var shown: String {
        if let revealedOverride { return revealedOverride }
        guard isRevealed else { return maskedOverride ?? String(repeating: "•", count: 10) }
        let value = value.reveal()
        // An empty field is still worth listing — the user put it there — but a row with
        // nothing after the label reads as a rendering fault rather than as "empty".
        return value.isEmpty ? "—" : value
    }

    /// Whether what is on screen is the empty-value placeholder rather than content.
    private var isPlaceholder: Bool {
        revealedOverride == nil && isRevealed && value.isEmpty
    }

    var body: some View {
        HStack(spacing: Design.Metrics.tightSpacing) {
            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)
                Text(shown)
                    .font(.callout.monospaced())
                    .foregroundStyle(isPlaceholder
                                     ? Design.Palette.secondaryText
                                     : Design.Palette.primaryText)
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
            // No copy button on an empty field: it would report "copied" having put
            // nothing on the clipboard.
            if !value.isEmpty {
                Button(action: onCopy) { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .help("Copy \(label)")
                    .accessibilityLabel("Copy \(label)")
            }
        }
        .padding(.vertical, Design.Metrics.rowVerticalPadding - 3)
        // Never speak a concealed value; announce its presence instead.
        .accessibilityElement(children: .contain)
    }
}

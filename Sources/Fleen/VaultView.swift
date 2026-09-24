import SwiftUI
import Combine
import FleenKit
import KdbxCore

/// The unlocked vault.
///
/// Two modes, switched by whether the search field has anything in it:
///
/// * **Tree** (empty search) — the group hierarchy as an expandable outline, the way
///   KeePassXC presents it: everything visible at once, groups opening in place.
/// * **Search** (anything typed) — a flat ranked list across the whole database,
///   ignoring the hierarchy. Once you are typing, you want the entry, not the tree.
struct VaultView: View {
    @Bindable var session: VaultSession
    let preferences: Preferences

    @State private var query = ""
    @State private var selection: UUID?
    @State private var focusSearch = false
    @State private var detailEntry: Entry?
    @State private var copyFeedback: String?
    /// Which entry is mid-cycle for quick copy, and until when.
    @State private var quickCopyCycle = QuickCopyCycle()
    @State private var expandedGroups: Set<UUID> = []
    @State private var expansionSeededFor: UUID?
    /// Drill-down mode only: the folder currently being shown. nil means the root.
    @State private var currentGroupID: UUID?
    @State private var menuAnchor = MenuAnchorBox()

    private var isSearching: Bool { !query.trimmingCharacters(in: .whitespaces).isEmpty }

    /// Changes whenever the visible list changes identity, so stale hover highlights
    /// on recycled rows are cleared.
    private var navigationToken: AnyHashable {
        AnyHashable([query, detailEntry?.id.uuidString ?? "",
                     currentGroupID?.uuidString ?? "root",
                     String(expandedGroups.count), session.browseMode.rawValue])
    }

    var body: some View {
        VStack(spacing: 0) {
            searchBar
            Divider()

            if session.hasExternalChanges { externalChangeBanner }
            if showsBreadcrumbBar { breadcrumbBar }

            if let detailEntry {
                EntryDetailView(
                    entry: detailEntry,
                    database: session.database,
                    preferences: preferences,
                    onCopied: showCopyFeedback)
                    .frame(maxHeight: .infinity)
            } else if isSearching {
                searchResults
            } else {
                switch session.browseMode {
                case .tree:    treeList
                case .folders: folderList
                }
            }
        }
        // One fixed size in every state. The popover used to shrink to its contents,
        // which meant it changed height as you opened a folder, searched, or opened an
        // entry — the window resizing under the pointer on every navigation.
        .frame(width: Design.Metrics.popoverWidth, height: Design.Metrics.popoverHeight)
        .overlay(alignment: .bottom) { toast }
        .onAppear {
            focusSearch = true
            seedExpansionIfNeeded()
            // A cycle belongs to one unlocked session, not to whatever was half-done
            // before the vault locked.
            quickCopyCycle.reset()
        }
        .onChange(of: session.database?.rootGroup.id) { _, _ in
            seedExpansionIfNeeded()
            currentGroupID = nil
        }
        // Switching display mode mid-session must not leave the other mode's state
        // pointing at something no longer on screen.
        .onChange(of: session.browseMode) { _, _ in
            currentGroupID = nil
            selection = nil
        }
        .onChange(of: currentGroupID) { _, _ in selection = nil }
        .onDisappear { copyFeedback = nil }
        .onChange(of: query) { _, _ in
            // Typing means the user is looking for something else; holding them in a
            // record they have moved on from makes the search box appear broken.
            if detailEntry != nil { detailEntry = nil }
            selection = isSearching ? visibleRows.first?.id : nil
        }
        .onReceive(NotificationCenter.default.publisher(for: .fleenCopyPassword)) { _ in
            diagnose("copyPassword"); copyPassword()
        }
        .onReceive(NotificationCenter.default.publisher(for: .fleenCopyUsername)) { _ in
            diagnose("copyUsername"); copyUsername()
        }
        .onReceive(NotificationCenter.default.publisher(for: .fleenCopyURL)) { _ in
            diagnose("copyURL"); copyURL()
        }
        .onReceive(NotificationCenter.default.publisher(for: .fleenCopyTOTP)) { _ in
            diagnose("copyTOTP"); copyTOTP()
        }
        .onReceive(NotificationCenter.default.publisher(for: .fleenFocusSearch)) { _ in
            focusSearch = true
        }
        .onReceive(NotificationCenter.default.publisher(for: .fleenExpandAll)) { _ in
            expandAll()
        }
        .onReceive(NotificationCenter.default.publisher(for: .fleenCollapseAll)) { _ in
            collapseAll()
        }
    }

    // MARK: - Rows

    private var treeNodes: [VaultTree.Node] {
        guard let database = session.database else { return [] }
        return VaultTree.flatten(root: database.rootGroup,
                                 expanded: expandedGroups,
                                 recycleBinID: session.recycleBinGroupID,
                                 showsRecycleBin: session.showsRecycleBin)
    }

    /// The folder being shown in drill-down mode.
    private var currentGroup: KdbxCore.Group? {
        guard let database = session.database else { return nil }
        guard let currentGroupID else { return database.rootGroup }
        return database.group(withID: currentGroupID) ?? database.rootGroup
    }

    private var folderNodes: [VaultTree.Node] {
        guard let group = currentGroup else { return [] }
        return VaultTree.children(of: group,
                                  recycleBinID: session.recycleBinGroupID,
                                  showsRecycleBin: session.showsRecycleBin,
                                  inRecycleBin: isBrowsingRecycleBin)
    }

    private var isBrowsingRecycleBin: Bool {
        guard let binID = session.recycleBinGroupID,
              let database = session.database,
              let currentGroupID,
              let trail = database.path(toGroup: currentGroupID) else { return false }
        return trail.contains { $0.id == binID }
    }

    private var searchMatches: [SearchIndex.Match] { session.search(query) }

    /// Search results reuse the tree's node type at depth 0, so one row renderer and
    /// one keyboard model serve both modes.
    private var visibleRows: [VaultTree.Node] {
        if isSearching {
            return searchMatches.map {
                VaultTree.Node(kind: .entry($0.record), depth: 0, parentID: nil)
            }
        }
        return session.browseMode == .tree ? treeNodes : folderNodes
    }

    private func seedExpansionIfNeeded() {
        guard let root = session.database?.rootGroup else { return }
        guard expansionSeededFor != root.id else { return }
        expansionSeededFor = root.id
        expandedGroups = VaultTree.initiallyExpanded(root: root)
    }

    // MARK: - Search bar

    private var searchBar: some View {
        HStack(alignment: .center, spacing: Design.Metrics.tightSpacing) {
            SearchField(
                text: $query,
                placeholder: "Search \(session.index.records.count) entries",
                focusRequested: $focusSearch,
                onMoveUp: moveSelection(by: -1),
                onMoveDown: moveSelection(by: 1),
                onSubmit: activateSelection,
                onCancel: escapePressed,
                onMoveLeft: collapseOrGoToParent,
                onMoveRight: expandOrEnter,
                onMoveToStart: { moveSelectionToEdge(first: true) },
                onMoveToEnd: { moveSelectionToEdge(first: false) },
                onPageUp: moveSelection(by: -pageSize),
                onPageDown: moveSelection(by: pageSize))
            .frame(height: Design.Metrics.controlHeight)

            optionsMenu
        }
        .padding(.horizontal, Design.Metrics.gutter)
        .padding(.vertical, Design.Metrics.barVerticalPadding)
    }

    private var optionsMenu: some View {
        Button {
            ActionsMenuPresenter.present(entries: actionEntries, from: menuAnchor)
        } label: {
            HStack(spacing: 2) {
                Image(systemName: "ellipsis")
                    .font(.system(size: 11, weight: .semibold))
                Image(systemName: "chevron.down")
                    .font(.system(size: 7, weight: .bold))
            }
            .foregroundStyle(Design.Palette.secondaryText)
            .frame(width: Design.Metrics.actionsButtonWidth,
                   height: Design.Metrics.controlHeight)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(
            RoundedRectangle(cornerRadius: Design.Metrics.controlCornerRadius,
                             style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: Design.Metrics.controlCornerRadius,
                             style: .continuous)
                .strokeBorder(Design.Palette.separator, lineWidth: 0.5)
        )
        // An invisible AppKit view behind the button, so the menu has something to
        // position itself under while the button keeps its SwiftUI styling.
        .background(MenuAnchor(box: menuAnchor))
        .hoverHighlight(cornerRadius: Design.Metrics.controlCornerRadius)
        .help("Actions")
        .accessibilityLabel("Actions menu")
    }

    /// The menu's contents, rebuilt on each click so enabled states are current.
    ///
    /// Key equivalents are declared here so AppKit draws them right-aligned, the way
    /// every other macOS menu does. They are display only — `MainMenu` owns the actual
    /// dispatch, so nothing is registered twice.
    private var actionEntries: [MenuEntry] {
        let entry = selectedEntry()

        var entries: [MenuEntry] = []

        if let entry {
            entries += [
                .header(entry.title.isEmpty ? "Selected entry" : entry.title),
                .item(title: "Copy Password", key: "c", modifiers: [.command, .option],
                      enabled: entry.password?.isEmpty == false, action: copyPassword),
                .item(title: "Copy Username", key: "b", modifiers: [.command, .option],
                      enabled: !entry.username.isEmpty, action: copyUsername),
                .item(title: "Copy Address", key: "u", modifiers: [.command, .option],
                      enabled: !entry.url.isEmpty, action: copyURL),
                .item(title: "Copy One-Time Code", key: "t", modifiers: [.command, .option],
                      enabled: entry.totp != nil, action: copyTOTP),
            ]
            if detailEntry == nil {
                entries.append(.item(title: "Show Details",
                                     action: { activateSelection() }))
            }
        }

        // Only the outline has anything to expand. In drill-down mode these would be
        // inert commands sitting in the menu with nothing to act on.
        if session.browseMode == .tree {
            entries += [
                .header("Folders"),
                .item(title: "Expand All", key: "]", action: expandAll),
                .item(title: "Collapse All", key: "[", action: collapseAll),
            ]
        }

        entries += [
            .header("Database"),
            .item(title: "Reload from Disk", key: "r",
                  action: { Task { await session.reload() } }),
            .item(title: "Lock Vault", key: "l", action: lockVault),

            .separator,
            .item(title: "Settings…", key: ",",
                  action: { SettingsWindowController.shared.show(preferences: preferences) }),
            .item(title: "Quit Fleen", key: "q", action: { NSApp.terminate(nil) }),
        ]

        return entries
    }

    // MARK: - Breadcrumbs

    /// In outline mode the indentation already shows the hierarchy, so a folder
    /// breadcrumb would be redundant — it appears only for an open record. In
    /// drill-down mode it is the only way back, so it is shown whenever nested.
    private var showsBreadcrumbBar: Bool {
        if detailEntry != nil { return true }
        guard !isSearching, session.browseMode == .folders else { return false }
        return currentGroupID != nil
    }

    /// Everything above the list. Now only an estimate for Page Up/Down, since the
    /// list itself takes whatever space is left by layout rather than by subtraction.
    private var chromeHeight: CGFloat {
        Design.Metrics.controlHeight
            + Design.Metrics.barVerticalPadding * 2
            + (showsBreadcrumbBar ? Design.Metrics.crumbHeight + 10 : 0)
            + 1
    }

    /// Folder trail for the current context.
    private var breadcrumbGroups: [KdbxCore.Group] {
        guard let database = session.database else { return [] }
        if let detailEntry {
            return database.path(toEntry: detailEntry.id) ?? [database.rootGroup]
        }
        return currentGroupID.flatMap { database.path(toGroup: $0) } ?? [database.rootGroup]
    }

    @ViewBuilder
    private var breadcrumbBar: some View {
        if session.database != nil {
            let trail = breadcrumbGroups
            let recordName = detailEntry.map { $0.title.isEmpty ? "Untitled" : $0.title }

            HStack(spacing: 3) {
                Button(action: navigateBack) {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 12, weight: .semibold))
                        .frame(width: Design.Metrics.crumbHeight,
                               height: Design.Metrics.crumbHeight)
                }
                .buttonStyle(.borderless)
                .hoverHighlight(cornerRadius: Design.Metrics.controlCornerRadius,
                                resetToken: navigationToken)
                .help("Back (esc)")
                .accessibilityLabel("Back")

                ScrollViewReader { proxy in
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 3) {
                            ForEach(Array(trail.enumerated()), id: \.element.id) { index, group in
                                if index > 0 { crumbSeparator }
                                crumb(
                                    // index 0 is the root group, whose name is internal.
                                    title: index == 0
                                        ? "All Entries"
                                        : (group.name.isEmpty ? "Untitled folder" : group.name),
                                    isCurrent: recordName == nil && index == trail.count - 1
                                ) {
                                    jump(to: group, isRoot: index == 0)
                                }
                                .id(Self.crumbID(group.id))
                            }
                            if let recordName {
                                crumbSeparator
                                crumb(title: recordName, isCurrent: true, action: {})
                                    .id(Self.recordCrumbID)
                            }
                        }
                        .padding(.vertical, 1)
                    }
                    // A deep trail overflows the bar, and the useful end is the right
                    // one: where you are now, not the root you started from. Scroll to
                    // the last crumb whenever the trail changes.
                    .task(id: breadcrumbScrollToken) {
                        // Yield first: `.task` already runs on the main actor, but the
                        // new crumbs have not been laid out yet at this point, so
                        // scrolling immediately targets stale geometry.
                        await Task.yield()
                        guard !Task.isCancelled else { return }
                        withAnimation(Design.animation()) {
                            proxy.scrollTo(lastCrumbID(trail: trail,
                                                       hasRecord: recordName != nil),
                                           anchor: .trailing)
                        }
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Design.Metrics.tightSpacing)
            .padding(.vertical, Design.Metrics.tightSpacing - 1)
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Location: "
                + (trail.map(\.name) + [recordName].compactMap { $0 })
                    .joined(separator: ", "))
        }
    }

    /// Clicking a crumb: drill-down navigates to it, the outline reveals it.
    private func jump(to group: KdbxCore.Group, isRoot: Bool) {
        detailEntry = nil
        switch session.browseMode {
        case .folders:
            currentGroupID = isRoot ? nil : group.id
        case .tree:
            revealGroup(group.id)
        }
    }

    private static let recordCrumbID = "crumb.record"

    private static func crumbID(_ id: UUID) -> String { "crumb.\(id.uuidString)" }

    /// Changes whenever the trail does, which is what re-triggers the scroll.
    private var breadcrumbScrollToken: AnyHashable {
        AnyHashable(breadcrumbGroups.map(\.id.uuidString)
            + [detailEntry?.id.uuidString ?? ""])
    }

    private func lastCrumbID(trail: [KdbxCore.Group], hasRecord: Bool) -> String {
        if hasRecord { return Self.recordCrumbID }
        return Self.crumbID(trail.last?.id ?? UUID())
    }

    private var crumbSeparator: some View {
        Image(systemName: "chevron.right")
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(Design.Palette.secondaryText)
            .accessibilityHidden(true)
    }

    private func crumb(title: String, isCurrent: Bool,
                       action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.callout)
                .lineLimit(1)
                // Cap one crumb's width so a single long folder name cannot crowd the
                // rest of the trail out of the bar; the middle is what gets dropped,
                // keeping both ends of the name readable.
                .truncationMode(.middle)
                .frame(maxWidth: Design.Metrics.crumbMaxWidth)
                .padding(.horizontal, Design.Metrics.tightSpacing + 2)
                .frame(height: Design.Metrics.crumbHeight)
        }
        .buttonStyle(.borderless)
        .foregroundStyle(isCurrent ? Design.Palette.primaryText
                                   : Design.Palette.secondaryText)
        .hoverHighlight(cornerRadius: Design.Metrics.controlCornerRadius,
                        resetToken: navigationToken)
        .disabled(isCurrent)
    }

    // MARK: - Lists

    @ViewBuilder
    private var treeList: some View {
        if session.index.records.isEmpty && treeNodes.isEmpty {
            StatusMessageView(
                symbol: "tray",
                title: "This database is empty",
                message: "Folders and entries you add in KeePassXC will appear here.")
                .frame(maxHeight: .infinity)
        } else {
            rowList(treeNodes)
        }
    }

    @ViewBuilder
    private var folderList: some View {
        if session.index.records.isEmpty && folderNodes.isEmpty {
            StatusMessageView(
                symbol: "tray",
                title: "This database is empty",
                message: "Folders and entries you add in KeePassXC will appear here.")
                .frame(maxHeight: .infinity)
        } else if folderNodes.isEmpty {
            let isNested = currentGroupID != nil
            let backTitle: String? = isNested ? "Go back" : nil
            let backAction: (() -> Void)? = isNested ? { navigateUp() } : nil
            StatusMessageView(
                symbol: "folder",
                title: "This folder is empty",
                message: "Nothing is stored here. Search to look across the whole database.",
                actionTitle: backTitle,
                action: backAction)
                .frame(maxHeight: .infinity)
        } else {
            rowList(folderNodes)
        }
    }

    @ViewBuilder
    private var searchResults: some View {
        if searchMatches.isEmpty {
            StatusMessageView(
                symbol: "magnifyingglass",
                title: "No matches",
                message: "Nothing matches “\(query)”. Try part of a title, username, address or tag.",
                actionTitle: "Clear search",
                action: { query = "" })
                .frame(maxHeight: .infinity)
        } else {
            rowList(visibleRows)
        }
    }

    private func rowList(_ rows: [VaultTree.Node]) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 1) {
                    ForEach(rows) { node in
                        Button {
                            // SwiftUI does not hand a Button its modifiers, so the flags
                            // are read from the event being handled right now.
                            let command = NSEvent.modifierFlags.contains(.command)
                            activate(node, via: command ? .commandClick : .click)
                        } label: {
                            rowView(node)
                                .selectableRow(isSelected: selection == node.id,
                                               resetToken: navigationToken)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .contextMenu { rowMenu(for: node) }
                        .id(node.id)
                    }
                }
                .padding(.horizontal, Design.Metrics.tightSpacing)
                .padding(.vertical, 4)
            }
            .frame(maxHeight: .infinity)
            .onChange(of: selection) { _, new in
                guard let new else { return }
                withAnimation(Design.animation()) { proxy.scrollTo(new, anchor: .center) }
            }
        }
    }

    @ViewBuilder
    private func rowView(_ node: VaultTree.Node) -> some View {
        switch node.kind {
        case .group(let group):
            GroupRow(group: group,
                     style: session.browseMode == .tree ? .outline : .prominent,
                     depth: node.depth,
                     isExpanded: expandedGroups.contains(group.id),
                     hasChildren: hasChildren(group),
                     onToggle: { toggle(group.id) })
        case .entry(let record):
            EntryRow(record: record,
                     depth: node.depth,
                     showsGroupPath: isSearching,
                     alignsWithDisclosure: !isSearching && session.browseMode == .tree)
        }
    }

    @ViewBuilder
    private func rowMenu(for node: VaultTree.Node) -> some View {
        switch node.kind {
        case .group(let group):
            if session.browseMode == .tree {
                Button(expandedGroups.contains(group.id) ? "Collapse" : "Expand") {
                    toggle(group.id)
                }
                Button("Expand All", action: expandAll)
                Button("Collapse All", action: collapseAll)
            } else {
                // Drill-down: a folder opens rather than expanding in place.
                Button("Open Folder") { activate(node) }
            }
        case .entry(let record):
            let id = record.id
            Button("Copy Password") { selection = id; copyPassword() }
            Button("Copy Username") { selection = id; copyUsername() }
            Button("Copy Address") { selection = id; copyURL() }
            if session.entry(withID: id)?.totp != nil {
                Button("Copy One-Time Code") { selection = id; copyTOTP() }
            }
            Divider()
            Button("Show Details") { openDetail(id) }
        }
    }

    private func hasChildren(_ group: KdbxCore.Group) -> Bool {
        let visibleSubgroups = group.groups.contains {
            session.showsRecycleBin || $0.id != session.recycleBinGroupID
        }
        return visibleSubgroups || !group.entries.isEmpty
    }

    // MARK: - Banners and status

    private var externalChangeBanner: some View {
        HStack(spacing: Design.Metrics.tightSpacing) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .foregroundStyle(Design.Palette.warning)
            VStack(alignment: .leading, spacing: 1) {
                Text("This database changed on disk").font(.caption.weight(.medium))
                Text("Another app saved over it.").font(.caption2)
                    .foregroundStyle(Design.Palette.secondaryText)
            }
            Spacer()
            Button("Reload") { Task { await session.reload() } }
                .controlSize(.small)
            Button("Ignore") { session.dismissExternalChangeNotice() }
                .controlSize(.small)
                .buttonStyle(.link)
        }
        .padding(.horizontal, Design.Metrics.gutter)
        .padding(.vertical, Design.Metrics.tightSpacing)
        .background(Design.Palette.warning.opacity(0.12))
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var toast: some View {
        if let copyFeedback {
            ToastView(text: copyFeedback)
        } else if ClipboardService.shared.secondsRemaining > 0 {
            ToastView(text: "Clipboard clears in \(ClipboardService.shared.secondsRemaining)s",
                      symbol: "clipboard",
                      tint: Design.Palette.secondaryText)
        }
    }

    // MARK: - Expansion

    private func toggle(_ groupID: UUID) {
        if expandedGroups.contains(groupID) {
            expandedGroups.remove(groupID)
        } else {
            expandedGroups.insert(groupID)
        }
    }

    private func expandAll() {
        guard let root = session.database?.rootGroup else { return }
        expandedGroups = VaultTree.allGroupIDs(root: root)
    }

    private func collapseAll() {
        expandedGroups = []
    }

    /// Opens every ancestor of a group and selects it — used when jumping back from a
    /// record whose folder may be collapsed.
    private func revealGroup(_ groupID: UUID) {
        detailEntry = nil
        guard let database = session.database,
              let trail = database.path(toGroup: groupID) else { return }
        for group in trail where group.id != database.rootGroup.id {
            expandedGroups.insert(group.id)
        }
        selection = groupID == database.rootGroup.id ? nil : groupID
    }

    // MARK: - Navigation

    private var pageSize: Int {
        max(1, Int((Design.Metrics.popoverHeight - chromeHeight)
                   / Design.Metrics.estimatedRowHeight) - 1)
    }

    private func moveSelection(by delta: Int) -> () -> Void {
        {
            let rows = visibleRows
            guard !rows.isEmpty else { return }
            guard let current = selection,
                  let index = rows.firstIndex(where: { $0.id == current }) else {
                selection = rows.first?.id
                return
            }
            selection = rows[(index + delta).clamped(to: 0...(rows.count - 1))].id
        }
    }

    private func moveSelectionToEdge(first: Bool) {
        let rows = visibleRows
        guard !rows.isEmpty else { return }
        selection = first ? rows.first?.id : rows.last?.id
    }

    /// → opens a closed folder, or steps into an open one.
    private func expandOrEnter() {
        guard !isSearching, let id = selection else { return }

        if session.browseMode == .folders {
            if let node = visibleRows.first(where: { $0.id == id }), node.isGroup {
                currentGroupID = id
            }
            return
        }

        guard let node = visibleRows.first(where: { $0.id == id }),
              let group = node.group else { return }

        if expandedGroups.contains(group.id) {
            // Already open: move to its first child, as an outline view does.
            let rows = visibleRows
            if let index = rows.firstIndex(where: { $0.id == id }), index + 1 < rows.count,
               rows[index + 1].depth > node.depth {
                selection = rows[index + 1].id
            }
        } else if hasChildren(group) {
            expandedGroups.insert(group.id)
        }
    }

    /// ← closes an open folder, otherwise moves to the enclosing one.
    private func collapseOrGoToParent() {
        guard !isSearching else { return }

        if session.browseMode == .folders {
            navigateUp()
            return
        }

        guard let id = selection,
              let node = visibleRows.first(where: { $0.id == id }) else { return }

        if let group = node.group, expandedGroups.contains(group.id) {
            expandedGroups.remove(group.id)
        } else if let parentID = node.parentID,
                  visibleRows.contains(where: { $0.id == parentID }) {
            selection = parentID
        }
    }

    private var actionableID: UUID? {
        // The entry whose details are open is what the user is looking at, so that is
        // what a copy command means — whatever the list selection happens to be. Without
        // this, opening an entry and pressing ⇧⌘C did nothing, because clearing a search
        // or changing folder had already reset `selection` to nil.
        if let detailEntry { return detailEntry.id }
        return selection ?? (isSearching ? visibleRows.first?.id : nil)
    }

    /// How the row was activated.
    ///
    /// Quick copy is on ⌘-click rather than on a plain click, so it takes nothing away:
    /// a click still opens the entry, and the copy sequence is there when wanted without
    /// a mode to be in. Return opens the entry too.
    enum Activation { case click, commandClick, keyboard }

    /// Return: folders open and close, entries show their details.
    private func activateSelection() {
        guard let id = actionableID,
              let node = visibleRows.first(where: { $0.id == id }) else { return }
        activate(node, via: .keyboard)
    }

    private func activate(_ node: VaultTree.Node, via activation: Activation = .keyboard) {
        selection = node.id
        switch node.kind {
        case .group(let group):
            switch session.browseMode {
            case .tree:
                guard hasChildren(group) else { return }
                toggle(group.id)
            case .folders:
                currentGroupID = group.id
            }
        case .entry(let record):
            guard preferences.quickCopy, activation == .commandClick else {
                openDetail(record.id)
                return
            }
            quickCopy(record.id)
        }
    }

    /// Repeated clicks on one entry walk its copy sequence: password then one-time code
    /// for a login, number then expiry then security code for a card.
    private func quickCopy(_ id: UUID) {
        selection = id
        guard let entry = session.entry(withID: id) else { return }

        let steps = QuickCopyStep.sequence(for: entry)
        guard let step = quickCopyCycle.next(for: id, steps: steps) else {
            // Nothing copyable at all. Saying so beats a click that silently does
            // nothing and reads as a bug.
            showCopyFeedback("Nothing to copy on this entry")
            return
        }

        guard let value = value(of: step, in: entry) else { return }
        ClipboardService.shared.copySecret(value, clearAfter: preferences.clipboardClearSeconds)

        // Say what the next click will do, rather than leaving the user to discover that
        // the same click now means something else.
        if let upcoming = quickCopyCycle.upcomingStep(for: id, steps: steps) {
            copyFeedback = "\(step.label) copied · ⌘-click again for \(upcoming.nextHint)"
        } else {
            showCopyFeedback("\(step.label) copied")
        }
    }

    private func value(of step: QuickCopyStep, in entry: Entry) -> String? {
        switch step {
        case .password:
            return entry.password?.reveal()
        case .oneTimeCode:
            return entry.totp?.code()
        case .cardNumber:
            // Bare digits: a payment form rejects the spaces.
            return entry.cardNumberField?.card.digits
        case .cardExpiry:
            return entry.cardExpiryField?.value.reveal()
        case .cardSecurityCode:
            return entry.cardSecurityCodeField?.value.reveal()
        }
    }

    private func navigateBack() {
        if detailEntry != nil {
            detailEntry = nil
            return
        }
        navigateUp()
    }

    /// Drill-down only: move to the enclosing folder.
    private func navigateUp() {
        guard session.browseMode == .folders else { return }
        guard let database = session.database, let currentGroupID,
              let trail = database.path(toGroup: currentGroupID), trail.count > 1 else {
            self.currentGroupID = nil
            return
        }
        let parent = trail[trail.count - 2]
        // The root is represented as nil, so going up from a top-level folder lands on
        // the state the vault opens in.
        self.currentGroupID = (parent.id == database.rootGroup.id) ? nil : parent.id
    }

    /// Esc backs out one step at a time.
    private func escapePressed() {
        if detailEntry != nil { detailEntry = nil }
        else if isSearching { query = "" }
        else if session.browseMode == .folders, currentGroupID != nil { navigateUp() }
        else { lockVault() }
    }

    /// Reports a received menu command and what it resolved to.
    ///
    /// Separates the two ways a shortcut can appear broken: never arriving (a dispatch
    /// problem) versus arriving with nothing to act on (a target problem). Guessing
    /// between those cost a round trip once already.
    private func diagnose(_ command: String) {
        guard ProcessInfo.processInfo.environment["FLEEN_DIAG"] == "1" else { return }
        let target = selectedEntry()?.title ?? "none"
        NSLog("FLEEN-DIAG: command %@ → target: %@ (detail: %@, selection: %@)",
              command, target,
              detailEntry?.title ?? "nil",
              selection.map { $0.uuidString.prefix(8).description } ?? "nil")
    }

    /// Locks and dismisses the popover together.
    ///
    /// Posted rather than calling `session.lock()` directly: locking while the popover
    /// stays open swaps in the unlock screen, and its automatic biometric prompt then
    /// appears — so asking to lock produced a Touch ID panel instead of a closed window.
    private func lockVault() {
        NotificationCenter.default.post(name: .fleenLockVault, object: nil)
    }

    private func openDetail(_ id: UUID) {
        guard let entry = session.entry(withID: id) else { return }
        detailEntry = entry
    }

    // MARK: - Copying

    private func selectedEntry() -> Entry? {
        guard let id = actionableID else { return nil }
        return session.entry(withID: id)
    }

    private func copyPassword() {
        guard let entry = selectedEntry(), let password = entry.password else { return }
        ClipboardService.shared.copySecret(password.reveal(),
                                           clearAfter: preferences.clipboardClearSeconds)
        showCopyFeedback("Password copied")
    }

    private func copyUsername() {
        guard let entry = selectedEntry(), !entry.username.isEmpty else { return }
        ClipboardService.shared.copyPlain(entry.username)
        showCopyFeedback("Username copied")
    }

    private func copyURL() {
        guard let entry = selectedEntry(), !entry.url.isEmpty else { return }
        ClipboardService.shared.copyPlain(entry.url)
        showCopyFeedback("Address copied")
    }

    private func copyTOTP() {
        guard let entry = selectedEntry(), let totp = entry.totp else { return }
        ClipboardService.shared.copySecret(totp.code(),
                                           clearAfter: preferences.clipboardClearSeconds)
        showCopyFeedback("One-time code copied")
    }

    private func showCopyFeedback(_ message: String) {
        copyFeedback = message
        Task {
            try? await Task.sleep(for: .seconds(2))
            if copyFeedback == message { copyFeedback = nil }
        }
    }
}

/// Indentation applied per tree level.
private let indentPerLevel: CGFloat = 14

/// A folder row, in one of two presentations.
struct GroupRow: View {

    enum Style {
        /// Compact, with a disclosure triangle — KeePassXC's group tree.
        case outline
        /// Large, with a trailing chevron — the drill-down mode's "click to open".
        case prominent
    }

    let group: KdbxCore.Group
    var style: Style = .outline
    var depth: Int = 0
    var isExpanded: Bool = false
    var hasChildren: Bool = true
    var onToggle: () -> Void = {}

    private var entryCount: Int { group.allEntries().count }
    private var name: String { group.name.isEmpty ? "Untitled folder" : group.name }

    var body: some View {
        switch style {
        case .outline:  outlineRow
        case .prominent: prominentRow
        }
    }

    private var outlineRow: some View {
        HStack(spacing: 6) {
            // The triangle is its own hit target, so a folder can be opened without
            // changing the selection — the behaviour an outline view is expected to have.
            Button(action: onToggle) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(Design.Palette.secondaryText)
                    .rotationEffect(.degrees(isExpanded ? 90 : 0))
                    .frame(width: 12, height: 12)
                    .opacity(hasChildren ? 1 : 0)
            }
            .buttonStyle(.plain)
            .disabled(!hasChildren)
            .accessibilityLabel(isExpanded ? "Collapse \(name)" : "Expand \(name)")

            Image(systemName: isExpanded ? "folder.fill" : "folder")
                .foregroundStyle(Design.Palette.accent)
                .frame(width: 16)
                .accessibilityHidden(true)

            Text(name).lineLimit(1)

            Spacer(minLength: 4)

            if entryCount > 0 {
                Text("\(entryCount)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(Design.Palette.secondaryText)
            }
        }
        .padding(.leading, CGFloat(depth) * indentPerLevel)
        .padding(.vertical, Design.Metrics.rowVerticalPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(name) folder, \(entryCount) entries")
        .accessibilityAddTraits(.isButton)
        .accessibilityHint(isExpanded ? "Collapses this folder" : "Expands this folder")
    }

    private var prominentRow: some View {
        HStack(spacing: 10) {
            Image(systemName: "folder.fill")
                .font(.system(size: 16))
                .foregroundStyle(Design.Palette.accent)
                .frame(width: 22)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                Text(name)
                    .font(.body)
                    .lineLimit(1)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(Design.Palette.secondaryText)
            }

            Spacer(minLength: 4)

            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Design.Palette.secondaryText)
                .accessibilityHidden(true)
        }
        .padding(.vertical, Design.Metrics.rowVerticalPadding + 3)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(name) folder, \(subtitle)")
        .accessibilityAddTraits(.isButton)
        .accessibilityHint("Opens this folder")
    }

    private var subtitle: String {
        let folders = group.groups.count
        var parts: [String] = []
        if folders > 0 { parts.append("\(folders) folder\(folders == 1 ? "" : "s")") }
        parts.append("\(entryCount) entr\(entryCount == 1 ? "y" : "ies")")
        return parts.joined(separator: ", ")
    }
}

/// One entry row.
struct EntryRow: View {
    let record: SearchIndex.Record
    var depth: Int = 0
    /// Only worth showing while searching — in the tree the indentation says where it is.
    var showsGroupPath: Bool = true
    /// Reserves the outline's disclosure-triangle column so entry icons line up under
    /// folder names. Pointless in drill-down mode, where no triangles exist.
    var alignsWithDisclosure: Bool = true

    var body: some View {
        HStack(spacing: 6) {
            if alignsWithDisclosure {
                // Lines the icon up with folder names, past the triangle column.
                Spacer().frame(width: 12)
            }

            Image(systemName: iconName)
                .foregroundStyle(iconTint)
                .frame(width: 16)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                Text(record.title.isEmpty ? "Untitled" : record.title)
                    .lineLimit(1)
                HStack(spacing: 4) {
                    if !record.username.isEmpty {
                        Text(record.username).lineLimit(1)
                    }
                    if showsGroupPath, !record.groupPath.isEmpty {
                        Text("· \(record.groupPath)").lineLimit(1)
                    }
                }
                .font(.caption)
                .foregroundStyle(Design.Palette.secondaryText)
            }

            Spacer(minLength: 4)

            if record.hasTOTP {
                Image(systemName: "clock.arrow.circlepath")
                    .foregroundStyle(Design.Palette.secondaryText)
                    .accessibilityHidden(true)
            }
            if record.attachmentCount > 0 {
                Image(systemName: "paperclip")
                    .foregroundStyle(Design.Palette.secondaryText)
                    .accessibilityHidden(true)
            }
        }
        .padding(.leading, CGFloat(depth) * indentPerLevel)
        .padding(.vertical, Design.Metrics.rowVerticalPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityDescription)
        .accessibilityAddTraits(.isButton)
        .accessibilityHint("Opens this entry’s details")
    }

    private var iconName: String {
        if record.isInRecycleBin { return "trash.fill" }
        return record.isExpired ? "exclamationmark.circle.fill" : "key.fill"
    }

    private var iconTint: Color {
        if record.isInRecycleBin { return Design.Palette.secondaryText }
        return record.isExpired ? Design.Palette.warning : Design.Palette.accent
    }

    private var accessibilityDescription: String {
        var parts = [record.title.isEmpty ? "Untitled entry" : record.title]
        if !record.username.isEmpty { parts.append("username \(record.username)") }
        if showsGroupPath, !record.groupPath.isEmpty { parts.append("in \(record.groupPath)") }
        if record.isInRecycleBin { parts.append("deleted") }
        if record.isExpired { parts.append("expired") }
        if record.hasTOTP { parts.append("has a one-time code") }
        if record.attachmentCount > 0 { parts.append("\(record.attachmentCount) attachments") }
        return parts.joined(separator: ", ")
    }
}

extension Comparable {
    func clamped(to range: ClosedRange<Self>) -> Self {
        min(max(self, range.lowerBound), range.upperBound)
    }
}

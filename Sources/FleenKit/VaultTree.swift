import Foundation
import KdbxCore

/// The flattened, expandable outline shown when not searching.
///
/// Modelled on KeePassXC: the whole hierarchy is visible at once and groups expand and
/// collapse in place, rather than replacing the list one level at a time. KeePassXC
/// splits groups and entries into two panes, which does not fit a 380pt popover, so
/// they share one indented outline here — a group's subgroups and entries appear
/// beneath it when it is open.
public struct VaultTree {

    public struct Node: Identifiable {
        public enum Kind {
            case group(Group)
            case entry(SearchIndex.Record)
        }

        public let kind: Kind
        /// Indentation level; the root's children are 0.
        public let depth: Int
        /// The enclosing group, for "collapse / go to parent" navigation.
        public let parentID: UUID?

        public init(kind: Kind, depth: Int, parentID: UUID?) {
            self.kind = kind
            self.depth = depth
            self.parentID = parentID
        }

        /// Display title — also what the tests assert the ordering on.
        public var title: String {
            switch kind {
            case .group(let group): return group.name
            case .entry(let record): return record.title
            }
        }

        public var id: UUID {
            switch kind {
            case .group(let group): return group.id
            case .entry(let record): return record.id
            }
        }

        public var isGroup: Bool {
            if case .group = kind { return true }
            return false
        }

        public var group: Group? {
            if case .group(let group) = kind { return group }
            return nil
        }
    }

    /// Builds the visible rows for the current expansion state.
    ///
    /// - Parameters:
    ///   - expanded: identifiers of groups currently open.
    ///   - recycleBinID: hidden unless `showsRecycleBin`.
    public static func flatten(root: Group,
                        expanded: Set<UUID>,
                        recycleBinID: UUID?,
                        showsRecycleBin: Bool,
                        inRecycleBin: Bool = false) -> [Node] {
        var nodes: [Node] = []
        appendChildren(of: root, depth: 0, expanded: expanded,
                       recycleBinID: recycleBinID, showsRecycleBin: showsRecycleBin,
                       inRecycleBin: inRecycleBin, into: &nodes)
        return nodes
    }

    private static func appendChildren(of group: Group, depth: Int,
                                       expanded: Set<UUID>,
                                       recycleBinID: UUID?,
                                       showsRecycleBin: Bool,
                                       inRecycleBin: Bool,
                                       into nodes: inout [Node]) {
        // Folders before entries at each level, but otherwise in the order the
        // database stores them. That order is the user's own arrangement in KeePassXC;
        // sorting alphabetically here would throw it away.
        let subgroups = group.groups
            .filter { showsRecycleBin || $0.id != recycleBinID }

        for subgroup in subgroups {
            nodes.append(Node(kind: .group(subgroup), depth: depth, parentID: group.id))
            guard expanded.contains(subgroup.id) else { continue }
            appendChildren(of: subgroup, depth: depth + 1, expanded: expanded,
                           recycleBinID: recycleBinID, showsRecycleBin: showsRecycleBin,
                           inRecycleBin: inRecycleBin
                               || (recycleBinID != nil && subgroup.id == recycleBinID),
                           into: &nodes)
        }

        for entry in group.entries {
            nodes.append(Node(
                kind: .entry(SearchIndex.Record(
                    id: entry.id,
                    title: entry.title,
                    username: entry.username,
                    url: entry.url,
                    groupPath: "",
                    tags: entry.tags,
                    hasTOTP: entry.totp != nil,
                    isExpired: entry.times.isExpired,
                    attachmentCount: entry.attachments.count,
                    isInRecycleBin: inRecycleBin)),
                depth: depth,
                parentID: group.id))
        }
    }

    /// The immediate contents of one group, for the drill-down display mode.
    ///
    /// Same ordering rule as the outline: folders first, then entries, each in the
    /// database's own order.
    public static func children(of group: Group,
                                recycleBinID: UUID?,
                                showsRecycleBin: Bool,
                                inRecycleBin: Bool = false) -> [Node] {
        var nodes: [Node] = []
        for subgroup in group.groups
            where showsRecycleBin || subgroup.id != recycleBinID {
            nodes.append(Node(kind: .group(subgroup), depth: 0, parentID: group.id))
        }
        for entry in group.entries {
            nodes.append(Node(
                kind: .entry(SearchIndex.Record(
                    id: entry.id,
                    title: entry.title,
                    username: entry.username,
                    url: entry.url,
                    groupPath: "",
                    tags: entry.tags,
                    hasTOTP: entry.totp != nil,
                    isExpired: entry.times.isExpired,
                    attachmentCount: entry.attachments.count,
                    isInRecycleBin: inRecycleBin)),
                depth: 0,
                parentID: group.id))
        }
        return nodes
    }

    /// Groups the database itself records as open.
    ///
    /// KDBX stores an `IsExpanded` flag per group, which KeePassXC writes when you
    /// expand one. Seeding from it means the tree opens the way the user last left it
    /// in KeePassXC rather than fully collapsed.
    public static func initiallyExpanded(root: Group) -> Set<UUID> {
        var result: Set<UUID> = []
        func walk(_ group: Group) {
            for child in group.groups {
                if child.isExpanded { result.insert(child.id) }
                walk(child)
            }
        }
        walk(root)
        return result
    }

    /// Every group in the tree, for expand-all.
    public static func allGroupIDs(root: Group) -> Set<UUID> {
        Set(root.allGroups().map(\.id)).subtracting([root.id])
    }
}

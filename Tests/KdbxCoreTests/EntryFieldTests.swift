import Testing
import Foundation
@testable import KdbxCore

/// Which fields an entry considers worth displaying.
@Suite("Entry fields")
struct EntryFieldTests {

    static func entry(_ fields: [String: FieldValue]) -> Entry {
        var entry = Entry()
        entry.fields = fields
        return entry
    }

    @Test("Standard fields are never custom fields")
    func excludesStandardFields() {
        let entry = Self.entry([
            Entry.titleField: .plain("T"),
            Entry.userNameField: .plain("u"),
            Entry.passwordField: .makeProtected("p"),
            Entry.urlField: .plain("https://example.com"),
            Entry.notesField: .plain("n"),
        ])
        #expect(entry.meaningfulCustomFields.isEmpty)
    }

    @Test("TOTP storage fields are excluded from custom fields")
    func excludesTOTPPlumbing() {
        // Showing the raw seed next to the live code it generates is both redundant
        // and a second place to read the secret from.
        for key in Entry.totpFieldKeys {
            let entry = Self.entry([key: .makeProtected("JBSWY3DPEHPK3PXP")])
            #expect(entry.meaningfulCustomFields.isEmpty, "\(key) should be hidden")
        }
    }

    @Test("Empty custom fields are excluded")
    func excludesEmptyValues() {
        let entry = Self.entry([
            "Empty Plain": .plain(""),
            "Empty Protected": .makeProtected(""),
            "Real": .plain("value"),
        ])
        #expect(Set(entry.meaningfulCustomFields.keys) == ["Real"])
    }

    @Test("Genuine custom fields are kept, protection intact")
    func keepsRealCustomFields() throws {
        let entry = Self.entry([
            Entry.titleField: .plain("T"),
            "API Token": .makeProtected("tok_live"),
            "Account ID": .plain("12345"),
            "otp": .plain("otpauth://totp/X?secret=JBSWY3DP"),
        ])

        let custom = entry.meaningfulCustomFields
        #expect(Set(custom.keys) == ["API Token", "Account ID"])
        #expect(custom["API Token"]?.isProtected == true)
        #expect(custom["Account ID"]?.isProtected == false)
    }

    @Test("An entry with only a TOTP field has no custom fields to list")
    func totpOnlyEntryHasNoCustomFields() throws {
        // This is the case that used to render a "Custom fields" heading with an
        // empty list under it.
        let entry = Self.entry([
            Entry.titleField: .plain("TOTP Entry"),
            "otp": .plain("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP"),
        ])
        #expect(entry.meaningfulCustomFields.isEmpty)
        #expect(entry.totp != nil, "the code itself must still be available")
    }

    @Test("Real databases filter as expected")
    func filtersRealFixture() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")

        let example = try #require(database.allEntries.first { $0.title == "Example Entry" })
        #expect(Set(example.meaningfulCustomFields.keys) == ["API Token", "Account ID"])

        let totpEntry = try #require(database.allEntries.first { $0.title == "TOTP Entry" })
        #expect(totpEntry.meaningfulCustomFields.isEmpty)

        let legacy = try #require(database.allEntries.first { $0.title == "TOTP Legacy" })
        #expect(legacy.meaningfulCustomFields.isEmpty,
                "TOTP Seed and TOTP Settings are plumbing, not user content")
    }

    /// What the detail view lists: everything the user put there, empty values included.
    /// The TOTP keys are excluded because the live code is displayed instead — the URI
    /// and seed are its ingredients, and printing them beside it is a second place to
    /// read the secret from.
    @Test("Empty fields are listed; TOTP plumbing is not")
    func allCustomFieldsKeepsUserContent() {
        let entry = Entry(fields: [
            Entry.titleField: .plain("Thing"),
            Entry.userNameField: .plain("someone"),
            Entry.passwordField: .makeProtected("hunter2"),
            "otp": .makeProtected("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
            "TOTP Seed": .makeProtected("JBSWY3DPEHPK3PXP"),
            "Empty note": .plain(""),
            "Real": .plain("value"),
        ])

        #expect(Set(entry.allCustomFields.keys) == ["Empty note", "Real"],
                "the empty field is kept; otp and TOTP Seed are not")
        #expect(Set(entry.meaningfulCustomFields.keys) == ["Real"],
                "the CLI's view drops empty values too")
    }

    /// The standard five stay out: they are shown in their own right above, so listing
    /// them again would be duplication rather than disclosure.
    @Test("The standard fields are not repeated among the custom ones")
    func standardFieldsExcluded() {
        let entry = Entry(fields: [
            Entry.titleField: .plain("Thing"),
            Entry.userNameField: .plain("someone"),
            Entry.passwordField: .makeProtected("hunter2"),
            Entry.urlField: .plain("https://example.com"),
            Entry.notesField: .plain("note"),
        ])
        #expect(entry.allCustomFields.isEmpty)
    }

    /// A TOTP entry shows a code and nothing else: no URI row, no seed row.
    @Test("A TOTP entry lists no fields, in either storage form")
    func totpEntriesListNoFields() throws {
        let database = try Fixture.open("pkp-aes-argon2d.kdbx")

        let modern = try #require(database.allEntries.first { $0.title == "TOTP Entry" })
        #expect(modern.allCustomFields.isEmpty, "the otpauth:// URI must not be listed")
        #expect(modern.totp != nil, "but the code itself is still available")

        let legacy = try #require(database.allEntries.first { $0.title == "TOTP Legacy" })
        #expect(legacy.allCustomFields.isEmpty, "nor the seed and settings pair")
        #expect(legacy.totp != nil)
    }
}

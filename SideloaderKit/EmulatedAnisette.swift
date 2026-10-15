// EmulatedAnisette.swift — local anisette for macOS 27+, ported from AltServer 1.8.1
// (altstoreio/AltStore commit fafd76e, "Local anisette generation for macOS 27").
//
// macOS 27 refuses anisette to non-Apple processes (adid: "CNE!", AOSKit -45070; akd
// cancels the XPC connection), and Apple rejects anisette from the shared public servers
// (Android client info → HTTP 503 at the edge; Mac client info → -80045). AltServer's
// answer: run Apple's own Android ADI libraries (libCoreADI.so / libstoreservicescore.so,
// taken from the Apple Music APK that Apple serves from apps.mzstatic.com) inside the
// Unicorn CPU emulator via AnisetteKit. Each Mac gets its own provisioned identity; no
// third-party server is involved.
//
// Synchronous wrapper (like the rest of Anisette.swift): the async AnisetteKit calls run in
// a detached Task and the caller waits on a semaphore. fresh() is only called from GCD /
// main-thread code paths, never from inside Swift concurrency.
import Foundation
import CryptoKit
import AltSign
import AnisetteKit

enum EmulatedAnisette {
    private static let apkURL = URL(string: "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk")!
    private static let idKey = "sidestep.emulatedAnisetteID"
    static let baseDir = URL(fileURLWithPath: SideStepSupportDir).appendingPathComponent("anisette-emulated")
    private static var provisioningDir: URL { baseDir.appendingPathComponent("provisioning") }
    private static var librariesDir: URL { baseDir.appendingPathComponent("libraries") }

    /// SIDESTEP_EMULATED_ANISETTE=0 disables this path (falls through to the server path).
    static var isEnabled: Bool { ProcessInfo.processInfo.environment["SIDESTEP_EMULATED_ANISETTE"] != "0" }

    enum Failure: Error { case message(String) }

    /// Returns anisette or a human-readable reason. Blocks up to `timeout` seconds
    /// (the first run downloads the Apple Music APK, so allow for that).
    static func fetch(timeout: TimeInterval = 300) -> Result<ALTAnisetteData, Failure> {
        final class Box: @unchecked Sendable { var value: Result<ALTAnisetteData, Failure>? }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        Task.detached {
            do { box.value = .success(try await fetchAsync()) }
            catch { box.value = .failure(.message(describe(error))) }
            done.signal()
        }
        guard done.wait(timeout: .now() + timeout) == .success, let r = box.value else {
            return .failure(.message("timed out after \(Int(timeout)) s"))
        }
        return r
    }

    private static func describe(_ error: Error) -> String {
        if let e = error as? Failure, case .message(let m) = e { return m }
        return (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
    }

    private static func identity() throws -> UUID {
        if let s = UserDefaults.standard.string(forKey: idKey), let id = UUID(uuidString: s) { return id }
        let id = UUID()
        UserDefaults.standard.set(id.uuidString, forKey: idKey)
        return id
    }

    private static func fetchAsync() async throws -> ALTAnisetteData {
        let id = try identity()
        try await prepareLibraries()
        do {
            return try await makeAnisette(for: id)
        } catch AnisetteKit.AnisetteError.adiError(let code, let description) {
            // A rejected provisioning never becomes valid again: drop it and provision anew.
            print("[SideStep anisette] emulated ADI error \(code) (\(description)) — re-provisioning")
            try? FileManager.default.removeItem(at: provisioningDir.appendingPathComponent(id.uuidString.lowercased()))
            return try await makeAnisette(for: id)
        }
    }

    /// Download Apple's Android ADI libraries once (only the two .so files are kept).
    private static func prepareLibraries() async throws {
        let fm = FileManager.default
        if AnisetteClient.validateLibrariesExist(at: librariesDir) { return }
        print("[SideStep anisette] downloading Apple's ADI libraries (Apple Music for Android) …")
        let (apk, response) = try await URLSession.shared.download(from: apkURL)
        defer { try? fm.removeItem(at: apk) }
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw Failure.message("APK download failed (HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1))")
        }
        try fm.createDirectory(at: librariesDir, withIntermediateDirectories: true)
        let tmp = try fm.url(for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: librariesDir, create: true)
        defer { try? fm.removeItem(at: tmp) }
        // The APK has case-insensitive duplicate names, so use /usr/bin/unzip and extract only
        // the two ARM64 libraries (AnisetteKit emulates an ARM64 CPU).
        let wanted = AnisetteConstants.Libraries.requiredNames.map { "lib/arm64-v8a/" + $0 }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        p.arguments = ["-o", "-j", "-q", apk.path] + wanted + ["-d", tmp.path]
        try p.run(); p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw Failure.message("unzip failed (\(p.terminationStatus))") }
        for name in AnisetteConstants.Libraries.requiredNames {
            let dest = librariesDir.appendingPathComponent(name)
            if fm.fileExists(atPath: dest.path) { try fm.removeItem(at: dest) }
            try fm.moveItem(at: tmp.appendingPathComponent(name), to: dest)
        }
        print("[SideStep anisette] ADI libraries ready")
    }

    private static func makeAnisette(for id: UUID) async throws -> ALTAnisetteData {
        // Emulated provider, as in AltServer: the native provider maps the Linux .so files as
        // executable code in-process, which a hardened/notarized app may not be allowed to do.
        let dir = librariesDir
        // ADI writes its state into the provisioning directory during provisioning; it must
        // exist beforehand, otherwise ADIProvisioningEnd fails with -45054 (filesystem error).
        // (AltServer gets this for free because its libraries live inside that directory.)
        try FileManager.default.createDirectory(at: provisioningDir.appendingPathComponent(id.uuidString.lowercased()),
                                                withIntermediateDirectories: true)
        let client = try AnisetteClient(provisioningDir: provisioningDir,
                                        provider: UnicornAnisetteDataProvider(),
                                        libraryDirectoryResolver: { dir })
        // AnisetteKit's default localUserID is shared by all its users and Apple rejects it.
        let raw = withUnsafeBytes(of: id.uuid) { Data($0) }
        let localUserID = SHA256.hash(data: raw).map { String(format: "%02X", $0) }.joined()
        var req = AnisetteRequestHeaders()
        req.localUserID = localUserID

        let (h, newBlob) = try await client.getAnisetteData(identifier: id, headers: req)
        if let newBlob { print("[SideStep anisette] provisioned emulated identity (\(newBlob.count) bytes)") }

        guard let mdm = h[AnisetteConstants.Headers.machineID] else { throw Failure.message("no machineID") }
        guard let md = h[AnisetteConstants.Headers.oneTimePassword] else { throw Failure.message("no oneTimePassword") }
        guard let rs = h[AnisetteConstants.Headers.routingInfo], let rinfo = UInt64(rs) else { throw Failure.message("no routingInfo") }

        let clientInfo = ProcessInfo.processInfo.environment["SIDESTEP_ANISETTE_CLIENTINFO"] ?? client.clientInfo
        return ALTAnisetteData(machineID: mdm, oneTimePassword: md, localUserID: localUserID, routingInfo: rinfo,
                               deviceUniqueIdentifier: id.uuidString.uppercased(),
                               deviceSerialNumber: AnisetteConstants.defaultSerialNumber,
                               deviceDescription: clientInfo, date: Date(), locale: .current, timeZone: .current)
    }
}

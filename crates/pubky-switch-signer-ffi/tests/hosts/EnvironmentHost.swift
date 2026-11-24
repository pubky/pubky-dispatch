// Host checks for the signer environment and protocol authority (Switch spec 3.2).
import Foundation
import PubkySwitchSigner

// The signer's file limit, 16 MiB (Switch wire 3.13).
private let fileLimit: UInt64 = 16 * 1024 * 1024

// A scope no registered protocol owns, with a sub-scope label another app chose.
private let unowned = "elsewhere:private-label"

// How a test Homeserver fails, if it does.
private enum Fault { case none, denied, unreachable, unexpected, failingPut, failingDelete, oversized }

private struct HostFault: Error { let text: String }

private actor MemoryHomeserver: HostHomeserver {
    private let fault: Fault
    private var files: [String: Data] = [:]
    private(set) var calls: [String] = []
    private(set) var limits: [UInt64] = []
    private(set) var written: Data?

    init(fault: Fault = .none) { self.fault = fault }

    func get(path: String, limit: UInt64) async throws -> Data? {
        calls.append("get \(path)")
        limits.append(limit)
        switch fault {
        case .denied: throw HomeserverFailure.Denied
        case .unreachable: throw HomeserverFailure.Unreachable
        case .unexpected: throw HostFault(text: "host fault \(unowned)")
        case .oversized: throw HomeserverFailure.TooLarge(limit: limit)
        default: break
        }
        return files[path]
    }

    func put(path: String, bytes: Data) async throws {
        calls.append("put \(path)")
        if fault == .failingPut { throw HomeserverFailure.Other }
        files[path] = bytes
        written = bytes
    }

    func delete(path: String) async throws {
        calls.append("delete \(path)")
        if fault == .failingDelete { throw HomeserverFailure.Other }
        files.removeValue(forKey: path)
    }
}

private func refusal(_ kind: RefusalKind, toApp: Data? = nil, stop: KeyRecoveryStopKind? = nil,
                     measurements: RefusalMeasurements? = nil, scopes: [String]? = nil) -> SignerFfiError {
    .Refused(kind: kind, sinceMs: nil, version: nil, toApp: toApp, install: nil,
             stop: stop, measurements: measurements, alert: nil,
             scopes: scopes.map { UnownedScopes(names: $0) })
}

private func service(_ kind: ServiceFailure, status: UInt16? = nil, authenticated: Bool,
                     code: String? = nil, retryAfterS: UInt64? = nil, retry: RetryKind? = nil,
                     transport: TransportFailure? = nil, limit: UInt64? = nil) -> SignerFfiError {
    .Service(kind: kind, status: status, authenticated: authenticated, code: code, retryAfterS: retryAfterS,
             retry: retry, notHosted: false, knownVersion: nil, transport: transport, limit: limit,
             generation: nil, serverTimeMs: nil, detail: nil)
}

/// The typed failure each sample gives (Switch spec 4.3).
private func expected(_ sample: SampleFailure) -> SignerFfiError {
    switch sample {
    case .clockOff: return refusal(.clockOff, measurements: .clockOff(deviceMs: 5, serviceMs: 9))
    case .handingOver: return refusal(.handingOver, toApp: Data(repeating: 3, count: 16))
    case .keyRecovery: return refusal(.keyRecovery, stop: .serviceBehind,
                                      measurements: .serviceBehind(serviceVersion: 2, seenVersion: 4))
    case .storeTooLarge: return .Store(kind: .tooLarge, size: 13, cap: 12)
    case .transportTooLarge: return service(.transport, authenticated: false, transport: .tooLarge, limit: 64)
    case .errorAnswer: return service(.errorAnswer, status: 429, authenticated: true, code: "rate_limited",
                                      retryAfterS: 37, retry: .afterRetryAfter)
    case .bodyUnread: return service(.bodyUnread, status: 429, authenticated: true, code: "rate_limited",
                                     retryAfterS: 19)
    case .unsignedStatus: return service(.badServiceSignature, status: 404, authenticated: false)
    case .undecodable: return .Records(kind: .undecodable, record: .flow, line: 7, column: 11, write: nil,
                                       size: nil, cap: nil)
    case .notNamed: return .NotNamed(install: Data(repeating: 5, count: 16))
    case .handedOver: return .HandedOver(install: Data(repeating: 7, count: 16))
    case .invalidData: return .InvalidData(kind: .invalid)
    case .storedData: return .StoredData(kind: .invalid)
    case .alarm: return .Alarm(alert: .backupUnreadable)
    }
}

private func texts(_ failure: SignerFfiError) -> [String] {
    [String(reflecting: failure), String(describing: failure), failure.localizedDescription]
}

private func checkSampleFailures() {
    for sample in sampleFailures() {
        do {
            try sampleFailure(sample: sample)
            check(false, "expected a signer failure")
        } catch let failure as SignerFfiError {
            check(failure == expected(sample), "wrong typed fields for \(sample)")
            check(!texts(failure).contains { $0.contains(fixtureText) }, "inner error text crossed the binding")
        } catch {
            check(false, "unexpected failure type")
        }
    }
}

private func checkScopeTerms() throws {
    let terms = try scopeTerms(scopes: ["sample-a"])
    check(terms.keyed == ["sample-a"] && terms.permissions == ["claims.read"], "sample authority")
    for (scope, wanted) in [("sample-b", refusal(.protocolRule)),
                            (unowned, refusal(.unknownScopes, scopes: [unowned]))] {
        do {
            _ = try scopeTerms(scopes: [scope])
            check(false, "expected a scope refusal")
        } catch let failure as SignerFfiError {
            check(failure == wanted, "scope refusal for \(scope)")
            // The field holds the name; the error's text never does.
            check(!texts(failure).contains { $0.contains("private-label") },
                  "a refused scope's name crossed in the error text")
        }
    }
}

private let path = "/sample"
private let bytes = Data([0, 255, 3])

private func failedTrip(_ fault: Fault, _ wanted: SignerFfiError, _ calls: [String]) async {
    let home = MemoryHomeserver(fault: fault)
    do {
        _ = try await homeserverRoundTrip(homeserver: home, path: path, bytes: bytes)
        check(false, "round trip with \(fault) succeeded")
    } catch let failure as SignerFfiError {
        check(failure == wanted, "round trip with \(fault)")
        check(!texts(failure).contains { $0.contains(unowned) }, "host text crossed the binding")
    } catch {
        check(false, "unexpected failure type")
    }
    check(await home.calls == calls.map { "\($0) \(path)" }, "calls with \(fault)")
}

private func checkHomeserver() async throws {
    let home = MemoryHomeserver()
    _ = try SignerEnvironment(homeserver: home, transport: TransportOptions())
    do {
        _ = try SignerEnvironment(homeserver: home, transport: TransportOptions(requestTimeoutMs: 0))
        check(false, "accepted a zero timeout")
    } catch let failure as SignerFfiError {
        check(failure == .InvalidInput(reason: "request_timeout_ms"), "zero timeout")
    }

    let trip = try await homeserverRoundTrip(homeserver: home, path: path, bytes: bytes)
    check(trip.absentBefore && trip.matchedAfterPut && trip.absentAfter, "homeserver round trip")
    check(await home.written == bytes, "host received the supplied bytes")
    let expectedCalls = ["get", "put", "get", "delete", "delete", "get"].map { "\($0) \(path)" }
    check(await home.calls == expectedCalls, "homeserver calls")
    let limits = await home.limits
    check(!limits.isEmpty && limits.allSatisfy { $0 == fileLimit }, "every read carries the file limit")

    func homeserver(_ kind: TransportFailure, size: UInt64? = nil) -> SignerFfiError {
        .Homeserver(kind: kind, size: size, status: nil)
    }
    await failedTrip(.denied, homeserver(.refused), ["get"])
    await failedTrip(.unreachable, homeserver(.connect), ["get"])
    await failedTrip(.unexpected, homeserver(.other), ["get"])
    await failedTrip(.oversized, homeserver(.tooLarge, size: fileLimit), ["get"])
    await failedTrip(.failingPut, homeserver(.other), ["get", "put"])
    await failedTrip(.failingDelete, homeserver(.other), ["get", "put", "get", "delete"])
}

/// Check the environment, scope terms and signer errors (Switch spec 3.2).
func checkEnvironment() async {
    do {
        try registerSampleProtocol()
        try registerSampleProtocol()
        check(try protocolNames() == ["sample"], "registered protocol names")
        try checkScopeTerms()
        checkSampleFailures()
        try await checkHomeserver()
    } catch {
        check(false, "unexpected environment failure")
    }
}

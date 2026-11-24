// Host checks for the signer environment and protocol authority (Switch spec 3.2).
package pubky.switch.signer.tests

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import pubky.switch.signer.*

// The signer's file limit, 16 MiB (Switch wire 3.13).
private const val FILE_LIMIT = 16_777_216uL

// A scope no registered protocol owns, with a sub-scope label another app chose.
private const val UNOWNED = "elsewhere:private-label"

// How a test Homeserver fails, if it does.
private enum class Fault { NONE, DENIED, UNREACHABLE, UNEXPECTED, FAILING_PUT, FAILING_DELETE, OVERSIZED }

private class MemoryHomeserver(private val fault: Fault = Fault.NONE) : HostHomeserver {
    private val files = ConcurrentHashMap<String, ByteArray>()
    val calls = CopyOnWriteArrayList<String>()
    val limits = CopyOnWriteArrayList<ULong>()
    @Volatile var written: ByteArray? = null
        private set

    override suspend fun get(path: String, limit: ULong): ByteArray? {
        calls.add("get $path")
        limits.add(limit)
        when (fault) {
            Fault.DENIED -> throw HomeserverFailure.Denied()
            Fault.UNREACHABLE -> throw HomeserverFailure.Unreachable()
            Fault.UNEXPECTED -> throw IllegalStateException("host fault $UNOWNED")
            Fault.OVERSIZED -> throw HomeserverFailure.TooLarge(limit)
            else -> {}
        }
        return files[path]?.copyOf()
    }

    override suspend fun put(path: String, bytes: ByteArray) {
        calls.add("put $path")
        if (fault == Fault.FAILING_PUT) throw HomeserverFailure.Other()
        files[path] = bytes.copyOf()
        written = bytes.copyOf()
    }

    override suspend fun delete(path: String) {
        calls.add("delete $path")
        if (fault == Fault.FAILING_DELETE) throw HomeserverFailure.Other()
        files.remove(path)
    }
}

private inline fun signerFailure(call: () -> Unit): SignerFfiException {
    try {
        call()
    } catch (failure: SignerFfiException) {
        return failure
    }
    throw IllegalStateException("expected a signer failure")
}

private fun bytes(n: Int, value: Int) = ByteArray(n) { value.toByte() }

private fun refusal(kind: RefusalKind, toApp: ByteArray? = null, stop: KeyRecoveryStopKind? = null,
                    measurements: RefusalMeasurements? = null, scopes: List<String>? = null) =
    SignerFfiException.Refused(kind, null, null, toApp, null, stop, measurements, null,
        scopes?.let { UnownedScopes(it) })

private fun service(kind: ServiceFailure, status: UShort? = null, authenticated: Boolean, code: String? = null,
                    retryAfterS: ULong? = null, retry: RetryKind? = null, transport: TransportFailure? = null,
                    limit: ULong? = null) =
    SignerFfiException.Service(kind, status, authenticated, code, retryAfterS, retry, false, null, transport,
        limit, null, null, null)

/** The typed failure each sample gives (Switch spec 4.3). */
private fun expected(sample: SampleFailure): SignerFfiException = when (sample) {
    SampleFailure.CLOCK_OFF -> refusal(RefusalKind.CLOCK_OFF, measurements = RefusalMeasurements.ClockOff(5uL, 9uL))
    SampleFailure.HANDING_OVER -> refusal(RefusalKind.HANDING_OVER, toApp = bytes(16, 3))
    SampleFailure.KEY_RECOVERY -> refusal(RefusalKind.KEY_RECOVERY, stop = KeyRecoveryStopKind.SERVICE_BEHIND,
        measurements = RefusalMeasurements.ServiceBehind(2uL, 4uL))
    SampleFailure.STORE_TOO_LARGE -> SignerFfiException.Store(StoreErrorKind.TOO_LARGE, 13uL, 12uL)
    SampleFailure.TRANSPORT_TOO_LARGE -> service(ServiceFailure.TRANSPORT, authenticated = false,
        transport = TransportFailure.TOO_LARGE, limit = 64uL)
    SampleFailure.ERROR_ANSWER -> service(ServiceFailure.ERROR_ANSWER, status = 429.toUShort(), authenticated = true,
        code = "rate_limited", retryAfterS = 37uL, retry = RetryKind.AFTER_RETRY_AFTER)
    SampleFailure.BODY_UNREAD -> service(ServiceFailure.BODY_UNREAD, status = 429.toUShort(), authenticated = true,
        code = "rate_limited", retryAfterS = 19uL)
    SampleFailure.UNSIGNED_STATUS -> service(ServiceFailure.BAD_SERVICE_SIGNATURE, status = 404.toUShort(),
        authenticated = false)
    SampleFailure.UNDECODABLE -> SignerFfiException.Records(RecordsFailure.UNDECODABLE, RecordKind.FLOW, 7uL, 11uL,
        null, null, null)
    SampleFailure.NOT_NAMED -> SignerFfiException.NotNamed(bytes(16, 5))
    SampleFailure.HANDED_OVER -> SignerFfiException.HandedOver(bytes(16, 7))
    SampleFailure.INVALID_DATA -> SignerFfiException.InvalidData(CoreFailure.INVALID)
    SampleFailure.STORED_DATA -> SignerFfiException.StoredData(CoreFailure.INVALID)
    SampleFailure.ALARM -> SignerFfiException.Alarm(AlertKind.BACKUP_UNREADABLE)
}

// Kotlin's exceptions compare by identity: compare the variant, every field through the
// message, and the byte fields by content, which the message prints by identity.
private fun sameFailure(actual: SignerFfiException, wanted: SignerFfiException): Boolean {
    fun text(failure: SignerFfiException) = failure.message.orEmpty().replace(Regex("""\[B@[0-9a-f]+"""), "[bytes]")
    fun fields(failure: SignerFfiException): List<ByteArray?> = when (failure) {
        is SignerFfiException.Refused -> listOf(failure.toApp, failure.install)
        is SignerFfiException.NotNamed -> listOf(failure.install)
        is SignerFfiException.HandedOver -> listOf(failure.install)
        else -> emptyList()
    }
    val pairs = fields(actual).zip(fields(wanted))
    return actual::class == wanted::class && text(actual) == text(wanted) &&
        fields(actual).size == fields(wanted).size &&
        pairs.all { (a, b) -> (a == null && b == null) || (a != null && b != null && a.contentEquals(b)) }
}

private fun checkSampleFailures() {
    for (sample in sampleFailures()) {
        val failure = signerFailure { sampleFailure(sample) }
        require(sameFailure(failure, expected(sample)), "wrong typed fields for $sample")
        require(!failure.toString().contains(FIXTURE_TEXT) && !failure.message.orEmpty().contains(FIXTURE_TEXT),
            "inner error text crossed the binding")
    }
}

private fun checkScopeTerms() {
    val terms = scopeTerms(listOf("sample-a"))
    require(terms.keyed == listOf("sample-a") && terms.permissions == listOf("claims.read"), "sample authority")
    for ((scope, wanted) in listOf("sample-b" to refusal(RefusalKind.PROTOCOL_RULE),
                                   UNOWNED to refusal(RefusalKind.UNKNOWN_SCOPES, scopes = listOf(UNOWNED)))) {
        val failure = signerFailure { scopeTerms(listOf(scope)) }
        require(sameFailure(failure, wanted), "scope refusal for $scope")
        require((failure as SignerFfiException.Refused).scopes == wanted.scopes, "refused scopes")
        // The field holds the name; the error's text never does.
        require(!failure.toString().contains("private-label") && !failure.message.orEmpty().contains("private-label"),
            "a refused scope's name crossed in the error text")
    }
}

private const val PATH = "/sample"
private val BYTES = byteArrayOf(0, -1, 3)

private suspend fun failedTrip(fault: Fault, wanted: SignerFfiException, calls: List<String>) {
    val home = MemoryHomeserver(fault)
    val failure = try {
        homeserverRoundTrip(home, PATH, BYTES)
        null
    } catch (failure: SignerFfiException) {
        failure
    }
    require(failure != null && sameFailure(failure, wanted), "round trip with $fault")
    require(!failure.toString().contains(UNOWNED), "host text crossed the binding")
    require(home.calls == calls.map { "$it $PATH" }, "calls with $fault")
}

private suspend fun checkHomeserver() {
    val home = MemoryHomeserver()
    SignerEnvironment(home, TransportOptions()).close()
    val invalid = signerFailure { SignerEnvironment(home, TransportOptions(requestTimeoutMs = 0uL)).close() }
    require(sameFailure(invalid, SignerFfiException.InvalidInput("request_timeout_ms")), "zero timeout")

    val trip = homeserverRoundTrip(home, PATH, BYTES)
    require(trip.absentBefore && trip.matchedAfterPut && trip.absentAfter, "homeserver round trip")
    require(home.written?.contentEquals(BYTES) == true, "host received the supplied bytes")
    require(home.calls == listOf("get", "put", "get", "delete", "delete", "get").map { "$it $PATH" },
        "homeserver calls")
    require(home.limits.isNotEmpty() && home.limits.all { it == FILE_LIMIT }, "every read carries the file limit")

    fun homeserver(kind: TransportFailure, size: ULong? = null) = SignerFfiException.Homeserver(kind, size, null)
    failedTrip(Fault.DENIED, homeserver(TransportFailure.REFUSED), listOf("get"))
    failedTrip(Fault.UNREACHABLE, homeserver(TransportFailure.CONNECT), listOf("get"))
    failedTrip(Fault.UNEXPECTED, homeserver(TransportFailure.OTHER), listOf("get"))
    failedTrip(Fault.OVERSIZED, homeserver(TransportFailure.TOO_LARGE, FILE_LIMIT), listOf("get"))
    failedTrip(Fault.FAILING_PUT, homeserver(TransportFailure.OTHER), listOf("get", "put"))
    failedTrip(Fault.FAILING_DELETE, homeserver(TransportFailure.OTHER), listOf("get", "put", "get", "delete"))
}

/** Check the environment, scope terms and signer errors (Switch spec 3.2). */
suspend fun checkEnvironment() {
    registerSampleProtocol()
    registerSampleProtocol()
    require(protocolNames() == listOf("sample"), "registered protocol names")
    checkScopeTerms()
    checkSampleFailures()
    checkHomeserver()
}

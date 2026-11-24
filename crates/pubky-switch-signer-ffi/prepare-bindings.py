"""Protect the generated descriptions of binding values.

UniFFI describes a record or an enum with fields field by field, in Kotlin's toString,
an exception's message and Swift's description and reflection. Every such value the
bindings generate is redacted unless it is on PUBLIC below, whose fields carry nothing a
host must keep private. A secret never crosses in such a value at all: it crosses into an
opaque handle (OPAQUE), which this script checks the generator kept opaque.
"""
from pathlib import Path
import re
import sys

# Values whose fields are public: an identity's public half, and the typed error with the
# measurements and service facts it carries, which name a failure's class, rule and numbers
# only. Text another app chose, such as the scopes of `UnownedScopes`, isn't here: its value
# is redacted, while the host still reads its fields.
PUBLIC = {"PublicIdentity", "SignerFfiException", "RefusalMeasurements", "ServiceDetail"}
# Every exported object: a handle a secret crosses into, or one that holds the host's own
# objects. Generated as objects, never described field by field, and used only through its
# own methods.
OPAQUE = {"HostSecret", "SignerEnvironment"}


def redact(kotlin_path, swift_source_path, swift_path):
    kotlin = kotlin_path.read_text()
    swift_source = swift_source_path.read_text()
    # UniFFI's buffer length already matches the JNA signature. Kotlin 2.3 diagnoses the
    # redundant conversion when the host build treats warnings as errors.
    length = "getByteBuffer(0, this.len.toLong())"
    if kotlin.count(length) != 1:
        raise ValueError("expected one generated JNA buffer method")
    kotlin = kotlin.replace(length, "getByteBuffer(0, this.len)")
    # An object lowered as an argument skips the guard against a closed handle, so every
    # exported object is listed here and checked below.
    objects = set(re.findall(r"^open class (\w+)\s*:\s*Disposable\b", kotlin, re.MULTILINE))
    if objects != OPAQUE:
        raise ValueError(f"exported objects not listed as opaque: {sorted(objects - OPAQUE)}")
    for name in OPAQUE:
        if not re.search(rf"^open class {name}\b", kotlin, re.MULTILINE):
            raise ValueError(f"{name} isn't generated as an opaque object")
        if re.search(rf"^(?:data|sealed) class {name}\b", kotlin, re.MULTILINE):
            raise ValueError(f"{name} is generated as a described value")
        # Lowered as an argument, a handle skips the guard a method call gets against a
        # handle the host closed: it is used only through its own methods.
        if f"FfiConverterType{name}.lower(" in kotlin:
            raise ValueError(f"{name} is passed as an argument")
    # A flat error carries its Display text as a message the script can't redact: errors
    # declare fields instead.
    flat = re.findall(r"^sealed class (\w+)\(message: String\)", kotlin, re.MULTILINE)
    if flat:
        raise ValueError(f"flat errors aren't redacted: {flat}")
    types = re.findall(r"^(?:data|sealed) class (\w+)\b", kotlin, re.MULTILINE)
    if not PUBLIC.issubset(types):
        raise ValueError("unexpected generated Kotlin value declarations")
    converters = {
        target: wire for wire, target in re.findall(
            r"^public object FfiConverterType(\w+)\s*:\s*FfiConverterRustBuffer<(\w+)>",
            kotlin, re.MULTILINE,
        )
    }
    swift = []
    for kotlin_name in types:
        if kotlin_name in PUBLIC:
            continue
        name = converters[kotlin_name]
        sealed = rf"^sealed class {kotlin_name}\b[^{{\n]*\{{\n"
        record = rf"^data class {kotlin_name} \(\n.*?^\)[^{{\n]*\{{\n"
        pattern = sealed if re.search(sealed, kotlin, re.MULTILINE) else record
        override = "final override" if pattern == sealed else "override"
        kotlin, count = re.subn(
            pattern,
            lambda m: m[0] + f'    {override} fun toString(): String = "{kotlin_name}(<redacted>)"\n',
            kotlin,
            flags=re.MULTILINE | re.DOTALL,
        )
        if count != 1:
            raise ValueError(f"expected one generated Kotlin declaration for {name}")
        thrown = re.search(rf"^sealed class {kotlin_name}\s*:\s*kotlin\.Exception\(\)",
                           kotlin, re.MULTILINE)
        if thrown:
            # An error, whatever its name: UniFFI also puts variant fields into its
            # Throwable.message.
            start = thrown.start()
            end = kotlin.index("\n}", start)
            body, count = re.subn(r'(override val message\n\s+get\(\) = )"[^\n]*"',
                                  r"\g<1>toString()", kotlin[start:end])
            variants = len(re.findall(r"^    (?:class|object) \w+", kotlin[start:end], re.MULTILINE))
            left = re.search(r'override val message\n\s+get\(\) = "', body)
            if not count or count != variants or left:
                raise ValueError(f"not every message of {kotlin_name} is redacted")
            kotlin = kotlin[:start] + body + kotlin[end:]
        if not re.search(rf"^public (?:struct|enum) {name}\b", swift_source, re.MULTILINE):
            raise ValueError(f"{name} isn't in the generated Swift")
        if re.search(rf"^extension {name}\s*:\s*[^{{]*CustomStringConvertible", swift_source,
                     re.MULTILINE):
            raise ValueError(f"the generated Swift already describes {name}")
        swift.append(f"""extension {name}: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {{
    public var description: String {{ "{name}(<redacted>)" }}
    public var debugDescription: String {{ description }}
    public var customMirror: Mirror {{ Mirror(self, children: [:]) }}
}}
""")
    kotlin_path.write_text(kotlin)
    swift_path.write_text("// Generated by prepare-bindings.py.\n" + "\n".join(swift))


if __name__ == "__main__":
    redact(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))

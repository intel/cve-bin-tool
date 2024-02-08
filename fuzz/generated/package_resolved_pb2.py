"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x16package_resolved.proto\x12\x08resolved"A\n\x0cPackageState\x12\x0e\n\x06\x62ranch\x18\x01 \x01(\t\x12\x10\n\x08revision\x18\x02 \x01(\t\x12\x0f\n\x07version\x18\x03 \x01(\t"[\n\nPackagePin\x12\x0f\n\x07package\x18\x01 \x01(\t\x12\x15\n\rrepositoryURL\x18\x02 \x01(\t\x12%\n\x05state\x18\x03 \x01(\x0b\x32\x16.resolved.PackageState"\x82\x01\n\x0fPackageResolved\x12\x30\n\x06object\x18\x01 \x01(\x0b\x32 .resolved.PackageResolved.Object\x12\x0f\n\x07version\x18\x02 \x01(\x05\x1a,\n\x06Object\x12"\n\x04pins\x18\x01 \x03(\x0b\x32\x14.resolved.PackagePinb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "package_resolved_pb2", _globals)
if _descriptor._USE_C_DESCRIPTORS is False:
    DESCRIPTOR._options = None
    _globals["_PACKAGESTATE"]._serialized_start = 36
    _globals["_PACKAGESTATE"]._serialized_end = 101
    _globals["_PACKAGEPIN"]._serialized_start = 103
    _globals["_PACKAGEPIN"]._serialized_end = 194
    _globals["_PACKAGERESOLVED"]._serialized_start = 197
    _globals["_PACKAGERESOLVED"]._serialized_end = 327
    _globals["_PACKAGERESOLVED_OBJECT"]._serialized_start = 283
    _globals["_PACKAGERESOLVED_OBJECT"]._serialized_end = 327
# @@protoc_insertion_point(module_scope)
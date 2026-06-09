# saksi-ffi-flutter

Flutter bridge facade for voter-facing Saksi operations. The crate exposes
FFI-safe DTOs and functions that `flutter_rust_bridge` can generate Dart
bindings for when the Flutter voter app lands.

The default build keeps the bridge testable without requiring Flutter tooling.
Enable the `frb` feature when running bridge code generation.


# Vendored pyflic-ble 0.2.6

Unmodified copy of the `pyflic_ble` package from
[pyflic-ble 0.2.6](https://pypi.org/project/pyflic-ble/0.2.6/)
(wheel sha256 `eb8348bcf68a00b4…`, source
<https://github.com/50ButtonsEach/pyflic-ble>), © Shortcut Labs AB,
licensed under the Apache License 2.0 (see `LICENSE`).

It is vendored rather than listed in `manifest.json` requirements because
Home Assistant core's `flic_button` integration pins the same package; a
different pin here could conflict with core. Flic Bluetooth uses it for Flic
Twist sessions and for the rotation tracker shared by Flic Duo and Twist.
Do not edit these files; update by replacing the directory with a newer
release and re-running the tests.

The library's own test suite runs against this copy from
`tests/vendored_pyflic` (imports repointed only).

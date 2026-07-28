# ha-flic-ble

## OVERVIEW
Home Assistant custom integration pairing Flic v2 / Flic Duo buttons directly over BLE (local adapter or ESPHome Bluetooth proxy), fully replacing the Flic Hub / `flicd`. Pure-Python reimplementation of Flic's v2 GATT + Chaskey-signed protocol. Stack: HA `bluetooth` component, `bleak-retry-connector`, `cryptography` (X25519/Ed25519), no external Flic deps.

## STRUCTURE
```
custom_components/flic_ble/
├── protocol.py       # 891 LOC — all wire protocol; NO homeassistant imports (unit-tested standalone)
├── runtime.py        # BLE transport: connect/reconnect, notify plumbing, config-entry persistence
├── config_flow.py    # discovery + one-shot pairing UI; maps protocol exceptions → error strings
├── const.py          # UUIDs, CONF_* keys, EVENT_TYPES, EVENT_FLIC_EVENT bus event name
├── entity.py         # FlicEntity base (DeviceInfo, availability)
├── event.py          # EventEntity + fires flic_ble_event on the HA bus
├── sensor.py         # battery-voltage sensor
├── device_trigger.py # device triggers = thin wrappers over the bus event
├── __init__.py       # entry setup; FlicDevice stored in entry.runtime_data (lazy import)
├── manifest.json     # bluetooth matcher (service_uuid 00420000-…, connectable)
├── strings.json / translations/en.json  # config-flow error keys
└── brand/            # icon assets
tests/test_protocol.py # pytest, protocol.py only (no HA runtime)
.github/scripts/build_release.sh  # zips integration to flic_ble.zip at archive root
FLIC_LICENSE.txt / NOTICE  # Chaskey code is a translation of Shortcut Labs' reference impl
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Pairing / discovery | `config_flow.py` + `runtime.async_pair_device` | full-verify handshake; button must be in public mode |
| Reconnect / persistent session | `runtime.FlicDevice` | quick-verify using stored `PairingData` |
| BLE proxy / adapter selection | `runtime.py` `async_ble_device_from_address(..., connectable=True)` + `_latest_device` | proxy failover via `ble_device_callback` |
| Press → HA event | `event.py` `_handle_event` | writes entity state AND fires `flic_ble_event` bus event |
| Automations / device triggers | `device_trigger.py` | wraps the bus event, NOT entity state |
| Protocol / crypto / decode | `protocol.py` | see CODE MAP |
| service_uuid matcher | `manifest.json` + `config_flow._is_supported_flic` | name `F2*` OR service uuid |
| Tests | `tests/test_protocol.py` | decoder + Chaskey vectors |

## CODE MAP
`protocol.py` (no HA deps — the real work):
- `FlicSession` — per-connection state machine. `SessionState` IDLE→WAIT_FULL_VERIFY_1/2 (new pair) or →WAIT_QUICK_VERIFY (stored pairing) →ESTABLISHED. Caller drives it: `start()`, `feed_gatt(bytes)`; awaits `pairing_complete` / `ready` events. Emits via `event_callback` / `state_callback`.
- `_defragment` — splits GATT notification into packets; handles 0x80 fragment bit and 0x40 multi-packet batching (first byte doubles as notification header + first packet header).
- `chaskey_signature` / `chaskey_16` / `chaskey_subkeys` — Chaskey-LTS MAC. 5-byte signed-packet authenticator; rx/tx counters; direction byte. Translated from Flic reference (see NOTICE).
- `_verify_button_certificate` — Ed25519 over `FLIC_ED25519_PUBLIC_KEY`; brute-forces 2 low bits of sig[32] (`sig_bits`), demands exactly one match.
- Session key: full-verify → SHA256(HMAC "SK"); quick-verify → `chaskey_16(pairing.key, msg)`.
- `decode_button_events` / `button_events_need_ack` — round v2 buttons (7-byte items).
- `decode_duo_button_events` + `_BitReader` — Duo packed little-endian bitstream; returns `DuoDecodeResult`. Big vs small button, swipes, accelerometer.

`runtime.py`:
- `FlicDevice.async_start` — registers ACTIVE bluetooth advert callback; each advert `_schedule_connect` (single-flight via `_connect_task`).
- `_async_establish_session` — `establish_connection` (bleak-retry, service cache), `start_notify(RX_UUID)`, feeds notifications into `FlicSession`, writes on `TX_UUID` with `response=False`.
- `_handle_state` — persists event counts / boot_id / battery back into `entry.data` via `async_update_entry` (so queued-event replay survives restart).

## CONVENTIONS
- `protocol.py` MUST stay free of `homeassistant` imports (kept unit-testable in isolation; tests import it directly with `pythonpath=["."]`).
- Addresses normalized `.upper()` everywhere; unique_id = uppercase BLE address.
- All persisted state lives in `entry.data` keyed by `CONF_*` from `const.py` (no options flow, no coordinator).
- Ruff: line-length 88, target py313, rules `E,F,I,UP,B,ASYNC`.
- Battery voltage = raw * 3.6 / 1024.0; accelerometer g = raw / 64.036875.

## ANTI-PATTERNS / GOTCHAS (THIS PROJECT)
- DO NOT drive automations off the event *entity's* state — use the `flic_ble_event` bus event / device triggers. A press queued while the button slept is delivered on reconnect; entity state was "unavailable" then, so a state trigger would drop it. (see `const.py` and `event.py` comments)
- Plain button up/down does NOT emit a user event — Flic follows it with a single-click-timeout packet; wait for that (`decode_button_events`). Emitting on up creates duplicate clicks.
- A recognized swipe suppresses its underlying single click, but never a double click; swipe emitted only from the release packet to avoid duplicate/repeat on the single-click timeout (`decode_duo_button_events`).
- Duo bitstream: stop while `unread_bytes > 1` — trailing bits + final byte are padding, not another update.
- Signed packets use separate rx/tx counters; reordering or replaying breaks the MAC (`AuthenticationError`).
- Flic v1 buttons unsupported (different undocumented protocol). Supported names start `F2`.
- Manifest `version` must equal the git tag `vX.Y.Z` — release workflow asserts it.
- Release archive must contain integration files at ITS ROOT (no `flic_ble/` prefix); `build_release.sh` enforces and bundles `FLIC_LICENSE.txt` + `NOTICE`.

## COMMANDS
```bash
python -m pip install -r requirements-test.txt
ruff check .
pytest -q                       # tests/test_protocol.py only
bash .github/scripts/build_release.sh   # produce/verify flic_ble.zip
```
Do NOT edit files under `.github/`.

## NOTES
- `iot_class: local_push`; `dependencies: ["bluetooth"]`; config_flow via bluetooth auto-discovery + user step.
- Connect timeouts: pairing 25s, establish 20s (ready), whole attempt 75s; auto-disconnect 511 (never) for paired sessions, 60 for pairing.
- Distributed only as a tagged HACS zip release (`hacs.json`, `content_in_root: false`).
- Chaskey / decoder logic is derived from Shortcut Labs AB's permissively-licensed Android reference — preserve `NOTICE` / `FLIC_LICENSE.txt` attribution.

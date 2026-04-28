Goal:
Create a Zephyr shell application for nRF9151 DK that demonstrates DECT NR+ communication between two boards.

Architecture:
- main.c handles shell commands and mode orchestration — no direct nrf_modem_dect.h dependency
- dect_adapter.h / dect_adapter.c encapsulate ALL nrf_modem_dect_* and nrf_modem_lib API calls
- main.c only includes dect_adapter.h; uses primitive types (uint8/16/32_t, bool, int, size_t) throughout
- Callbacks are defined in dect_adapter.h using plain types only (no nrf_modem enums or structs in the public API)

Important API note:
- The intended API level is the higher-level DECT MAC API:
  https://docs.nordicsemi.com/bundle/nrfxlib-apis-latest/page/group_nrf_modem_dect.html
- nrf_modem_dect.h is only included in dect_adapter.c

Callback context — CRITICAL:
- All nrf_modem_dect op and ntf callbacks run in a restricted modem library context
  (treat as ISR: no blocking, no re-entrant modem API calls).
- Permitted in callbacks: k_sem_give, k_msgq_put(K_NO_WAIT), k_work_submit/reschedule, LOG_DBG.
- Forbidden in callbacks: k_mutex_lock(K_FOREVER), any nrf_modem_dect_* API call, printk, LOG_INF/ERR.
- Pattern used in main.c: callbacks are minimal — they put a typed app_event onto app_evt_msgq
  (K_NO_WAIT) and return immediately. All logic runs in the main event loop (thread context)
  via process_*_event() handlers. complete_wait() (k_sem_give) may also be called in callbacks
  where the main thread is blocking on op_sem.
- dect_adapter.c internal callbacks: LOG_DBG only + dispatch to app callback. No LOG_INF.

Environment:
- Primary NCS version: 3.3.0
- A preview NCS tree is available at `/opt/nordic/ncs/main`
- Build output directory: '~/code/mac_demo/build'
- nrfutil location: `/opt/nordic/ncs/toolchains/561dce9adf/nrfutil/bin/nrfutil`
  (must be in PATH or called with full path — not in system PATH by default)

Target hardware:
- Board: nRF9151 DK (target: nrf9151dk/nrf9151/ns)
- Two boards connected for build/flash/test validation
- Serial numbers: 1052092657 and 1052013419
- UART ports (vcom0, 115200 baud):
  - 1052092657: /dev/tty.usbmodem0010520926571
  - 1052013419: /dev/tty.usbmodem0010520134191

Transport and payload rules:
- Payloads are ASCII text
- UART shell is the control interface (vcom0 on each board, 115200 baud)

Shell commands:
- `SEND <ascii text>`
- `FT` — RSSI scan, select least busy channel, start beaconing
- `PERIOD <ms>` — beacon period for FT device
- `PT` — scan all channels in band, find FT beacon, associate
- `CHANNEL <uint16>` — when given while in FT mode, skips RSSI scan and beacons directly on that channel
- `POWERSAVE 1|0` — toggles power saving and re-initializes radio
- `STATUS` — reports mode, channel, FT period, PT scan time, power save state

Current runtime defaults:
- FT period: 1000 ms
- PT scan time: 2000 ms

Mode behavior:
- FT: performs RSSI scan across all channels in the band, selects least busy channel,
  configures cluster beacon + network beacon, waits for PT association.
  Once PT is associated, FT can send/receive DLC messages.
  CHANNEL <N> while in FT skips RSSI scan and beacons on channel N directly.

- PT: scans ALL channels in the band (num_channels=0 in network scan params) to find an
  FT beacon. Once a network/cluster beacon is received, PT subscribes to cluster beacons
  and initiates association. Then PT can send/receive DLC messages.
  Note: FT must be beaconing before PT can associate. Send from either side only works
  after association is established.

Flashing — CRITICAL:
- Must flash merged.hex (TF-M + application), NOT zephyr.hex (app only):
    /opt/nordic/ncs/main/build/merged.hex   ← CORRECT
    /opt/nordic/ncs/main/build/mac_demo/zephyr/zephyr.hex  ← WRONG (no TF-M, board won't boot)
- Must reset after programming, device does NOT boot automatically:
    nrfutil device program --serial-number <SN> --firmware merged.hex --traits jlink
    nrfutil device reset --serial-number <SN>
- Without --traits jlink the command exits silently with 0 but may not program anything

Recovery (unresponsive board):
- If a board does not respond or is in a bad state, use recover before reflashing:
    nrfutil device recover --serial-number <SN>
    nrfutil device program --serial-number <SN> --firmware merged.hex --traits jlink
    nrfutil device reset --serial-number <SN>
- recover performs ERASEALL via CTRL-AP, disables AP-Protect, and clears all flash
- recover exit 0 = success; board is then blank and ready to program
- Verified working on nRF9151 DK (PCA10201)

Console / logging:
- CONFIG_UART_CONSOLE=y — logs go to UART (vcom0)
- CONFIG_RTT_CONSOLE=n — do NOT use RTT; RTT sends logs to J-Link only, nothing on UART
- Shell prompt: `dect-mac:~$ `

Test sequence:
1. Flash merged.hex to both boards (with reset after each)
2. FT board: send `FT` — wait ~10-15s for RSSI scan to complete and beaconing to start
3. PT board: send `PT` — PT will scan all channels, find FT, subscribe to cluster beacons, associate
4. Wait for PT association (check `STATUS` on FT shows associated, or watch for association_ind log)
5. FT sends first: `SEND <text>` (FT must have an associated PT to send)
6. PT sends: `SEND <text>` (PT must be associated to send)
- Do NOT send before association is confirmed; SEND returns -ENOTCONN (-128) if not associated

Validation requirements:
- Build for `nrf9151dk/nrf9151/ns`
- Flash both attached boards using merged.hex with explicit reset
- Serial monitor on /dev/cu.usbmodem* at 115200 baud

Implementation status:
- Adapter layer: complete — dect_adapter.h has no nrf_modem types; all API isolated in dect_adapter.c
- Shell commands: all 8 implemented (SEND, FT, PT, STATUS, CHANNEL, PERIOD, WINDOW, POWERSAVE)
- RSSI scan + channel selection: implemented in FT mode startup
- CHANNEL override: implemented — skips RSSI scan when user sets channel explicitly
- PT broadband scan: implemented — scans all channels in band (num_channels=0)
- LED indicators: simplified (FT=all on, PT=blinking); full state progression not yet implemented

Execution guidance:
- Keep build, flash, and serial test commands documented locally
- Record any DECT MAC vs DECT PHY assumptions explicitly
- If a behavior works only with raw PHY workarounds, call that out as provisional

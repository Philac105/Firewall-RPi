# Development

## Build

`cmake -S . -B build && cmake --build build -j`

## Run

`sudo ./build/Firewall_RPi --iface wlan0 --cpu 3`

## Features

Included:

- Capture pipeline returns explicit status (`Ipv4Ready`, `IgnoredPacket`, `Timeout`, `StreamEnded`, `FatalError`).
- IPv4 metadata parse (protocol, src/dst IPv4, ports, TCP flags).
- ACL + default deny, stateful reverse-flow pass, and per-source token-bucket rate limit.
- Periodic telemetry for pass/drop/timeout, latency stats, and rule-hit counters.

Not currently included:

- Dynamic ACL reload at runtime.
- Flow eviction redesign from FIFO to LRU.

## Rules Explained

Policy rules (counter names shown in logs):

- est: Stateful established-flow fast path (reverse-flow match). This is evaluated before static ACL rules.
- p22: Allow TCP destination port 22 (SSH).
- p443: Allow TCP destination port 443 (HTTPS).
- p53u: Allow UDP destination port 53 (DNS UDP).
- p53t: Allow TCP destination port 53 (DNS TCP).
- deny: Default deny-all fallback for packets that match none of the allow rules above.

Telemetry fields in periodic logs:

- Logs are emitted every 5 seconds and include a wall-clock timestamp.
- pass: Packets accepted by policy in the current 5-second interval.
- drop: Parsed IPv4 packets dropped by policy or WCET fail-safe in the current interval.
- ign: Packets ignored at capture parse stage (non-IPv4/truncated/invalid headers) in the current interval.
- tout: Capture read timeouts in the current interval.
- lat min/avg/max: Processing latency stats for packets that reached policy evaluation.
- wcet_viol: Count of packets that exceeded WCET threshold and were dropped fail-safe.
- rate_drop: Count of packets dropped by token-bucket limiter after ACL pass in the current interval.

Rule counters (`est`, `p22`, `p443`, `p53u`, `p53t`, `deny`) are interval counters and reset after each report line.

## Validation Tests

Quick smoke sequence:

1) Start firewall and verify no startup error:

`sudo ./build/Firewall_RPi --iface wlan0 --cpu 3`

2) Send allowed SSH traffic and expect pass counters to increase:

`hping3 -S -p 22 -c 50 <TARGET_IP>`

3) Send blocked traffic and expect drop counters to increase:

`hping3 -S -p 12345 -c 50 <TARGET_IP>`

4) Leave traffic idle for a few windows and expect timeout counters to increase.

Extended validation matrix:

1) Baseline capture loop and telemetry:

`sudo ./build/Firewall_RPi --iface wlan0 --cpu 3`

2) ACL allow test (SSH):

`hping3 -S -p 22 -c 200 <TARGET_IP>`

3) ACL default deny test (blocked port):

`hping3 -S -p 12345 -c 200 <TARGET_IP>`

4) Rate-limit stress test:

`hping3 --flood -S -p 12345 <TARGET_IP>`

5) Prioritized admin traffic during load (run while flood is active):

`hping3 -S -p 22 -i u5000 -c 500 <TARGET_IP>`

6) Realtime baseline and network baseline:

`sudo cyclictest -a 3 -t1 -p95 -m -i1000 -D60s -h400 -q > testing/cyclictest_hist_cpu3.log`
`sudo hping3 -S -p 80 -c 1000 <TARGET_IP> > testing/hping3_baseline.log`

# Development

## Build

`cmake -S . -B build && cmake --build build -j`

## Run

`sudo ./build/Firewall_RPi --iface wlan0 --cpu 3`

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

1) Baseline capture loop and telemetry:

`sudo ./build/Firewall_RPi --iface wlan0 --cpu 3`

2) ACL allow test (SSH):

`hping3 -p 22 -c 200 <TARGET_IP>`

3) ACL default deny test (blocked port):

`hping3 -p 12345 -c 200 <TARGET_IP>`

4) Rate-limit stress test:

`hping3 --flood -p 12345 <TARGET_IP>`

5) Prioritized admin traffic during load (run while flood is active):

`hping3 -p 443 -i u5000 -c 500 <TARGET_IP>`

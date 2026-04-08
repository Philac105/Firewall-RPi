# Development

## Build

`cmake -S . -B build && cmake --build build -j`

## Run

`sudo ./build/Firewall_RPi --iface wlan0 --cpu 3`

## Validation Tests

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

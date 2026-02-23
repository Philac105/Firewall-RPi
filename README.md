# Development

## Build

`cmake -S . -B build && cmake --build build -j`

## Run

`sudo ./build/Firewall_RPi --iface wlan0 --cpu 3`

# Test

`sudo cyclictest -a 3 -t1 -p95 -m -i1000 -D60s -h400 -q > cyclictest_hist_cpu3.log`
`sudo hping3 -S -p 80 -c 1000 <TARGET_IP> > hping3_baseline.log`

10.0.0.214
# systemd deployment

## Install service

```bash
sudo cp deployment/systemd/firewall-rpi.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable firewall-rpi
sudo systemctl start firewall-rpi
```

## Check health

```bash
sudo systemctl status firewall-rpi
journalctl -u firewall-rpi -f
```

## Crash-recovery test

```bash
sudo pkill -9 Firewall_RPi
sleep 2
sudo systemctl status firewall-rpi
```

The service is configured with:

- `Restart=always` and `RestartSec=1` for fast restart after failures.
- `WatchdogSec=10` as the software watchdog window.
- `CPUAffinity=3` and RT limits to preserve deterministic scheduling behavior.

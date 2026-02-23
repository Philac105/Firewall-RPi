# WiFi Hotspot Setup

The Raspberry Pi acts as a WiFi access point (AP) on `wlan0`, while using `eth0` (ethernet) for internet. All client
traffic passes through the firewall.

```
[Internet] ← eth0 (10.0.0.x) ← RPi (NAT) ← wlan0 AP (10.42.0.1) ← [Clients]
```

## Start the hotspot

```bash
sudo nmcli device wifi hotspot ifname wlan0 ssid "Firewall-RPi" password "motdepasse!"
```

## Make it persistent across reboots

```bash
sudo nmcli connection modify Hotspot connection.autoconnect yes connection.autoconnect-priority 100
sudo nmcli connection modify "netplan-wlan0-DEMI OCTET" connection.autoconnect no
```

## Switch back to normal WiFi

```bash
sudo nmcli connection down Hotspot
sudo nmcli connection up "netplan-wlan0-DEMI OCTET"
```

## Hotspot details

- **SSID**: `Firewall-RPi`
- **Password**: `motdepasse!`
- **Client subnet**: `10.42.0.0/24`
- **Gateway**: `10.42.0.1`
- **NAT/forwarding**: handled automatically by NetworkManager + nftables
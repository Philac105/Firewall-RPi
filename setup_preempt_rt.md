# PREEMPT_RT Kernel Setup

This guide explains how to build and install a real-time (PREEMPT_RT) kernel for Raspberry Pi.

## Prerequisites

Ensure you have sufficient disk space (10+ GB) and time (~2 hours for compilation).

## Setup Directory

```bash
mkdir ~/rt-kernel
cd ~/rt-kernel
```

## Download Kernel and RT Patch

Clone Raspberry Pi Linux kernel 6.12:
```bash
git clone --depth=1 --branch rpi-6.12.y https://github.com/raspberrypi/linux
```

Download the real-time patch:
```bash
wget https://cdn.kernel.org/pub/linux/kernel/projects/rt/6.12/older/patch-6.12.57-rt14.patch.gz
```

## Apply RT Patch

```bash
cd ~/rt-kernel/linux
zcat ../patch-6.12.57-rt14.patch.gz | patch -p1
```

## Configure Kernel

Load the base configuration:
```bash
make bcm2711_defconfig
```

Open the menu configuration:
```bash
make menuconfig
```

Navigate to **General Setup** and enable:
- **Fully Preemptible Kernel (Real-Time)**

## Build Kernel

Compile the kernel (this takes approximately 2 hours):
```bash
make -j4 Image modules dtbs
```

## Install Kernel

Install kernel modules:
```bash
sudo make modules_install
```

Copy the kernel image (using a different name to preserve the original):
```bash
sudo cp arch/arm64/boot/Image /boot/firmware/kernel8-rt.img
```

Copy device tree binaries:
```bash
sudo cp arch/arm64/boot/dts/broadcom/*.dtb /boot/firmware/
sudo cp arch/arm64/boot/dts/overlays/*.dtbo /boot/firmware/overlays/
```

## Configure Boot

Edit the boot configuration:
```bash
sudo nano /boot/firmware/config.txt
```

Add the following line under the `[all]` section:
```
kernel=kernel8-rt.img
```

## Reboot and Verify

Reboot the system:
```bash
sudo reboot
```

Verify the RT kernel is running:
```bash
uname -a
```

You should see `PREEMPT_RT` in the output.

## CPU Isolation (Optional)

To isolate CPU 3 for real-time tasks:

Edit the kernel command line:
```bash
sudo nano /boot/firmware/cmdline.txt
```

Add the following parameters to the end of the existing line (do not create a new line):
```
isolcpus=3 nohz_full=3 rcu_nocbs=3
```

Reboot to apply changes:
```bash
sudo reboot
```

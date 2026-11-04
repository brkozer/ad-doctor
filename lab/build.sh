#!/usr/bin/env bash
# Build the adlab DC VM (Windows Server 2025 eval) on this host.
# The guest is on QEMU user networking: only localhost ports are forwarded to it and it
# cannot reach any network itself.
set -euo pipefail
cd ~/adlab

if [ ! -f creds ]; then
  umask 077
  gen() { python3 -c 'import secrets,string;a=string.ascii_letters+string.digits;print("Ad1!"+"".join(secrets.choice(a) for _ in range(20)))'; }
  printf 'ADMIN_PASSWORD=%s\nDSRM_PASSWORD=%s\n' "$(gen)" "$(gen)" > creds
fi
. ./creds
[ -f ~/.ssh/adlab_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C adlab -f ~/.ssh/adlab_ed25519

rm -rf cfg && mkdir -m 700 cfg
sed "s|__ADMIN_PASSWORD__|$ADMIN_PASSWORD|g" autounattend.xml > cfg/autounattend.xml
cp setup.ps1 cfg/
cp ~/.ssh/adlab_ed25519.pub cfg/authorized_keys
printf '%s' "$DSRM_PASSWORD" > cfg/dsrm.txt
xorriso -as mkisofs -quiet -J -r -V ADLABCFG -o cfg.iso cfg
rm -rf cfg

sudo install -d -o libvirt-qemu -g kvm -m 750 /var/lib/libvirt/images/adlab
sudo cp ws2025.iso cfg.iso /var/lib/libvirt/images/adlab/
sudo qemu-img create -q -f qcow2 /var/lib/libvirt/images/adlab/dc01.qcow2 40G
sudo chown libvirt-qemu:kvm /var/lib/libvirt/images/adlab/*

virt-install --connect qemu:///system --name adlab-dc01 \
  --memory 3072 --vcpus 2 --cpu host-passthrough --os-variant win2k22 \
  --boot hd,cdrom \
  --disk /var/lib/libvirt/images/adlab/dc01.qcow2,bus=sata \
  --disk /var/lib/libvirt/images/adlab/ws2025.iso,device=cdrom,bus=sata \
  --disk /var/lib/libvirt/images/adlab/cfg.iso,device=cdrom,bus=sata \
  --network none --graphics vnc,listen=127.0.0.1 --noautoconsole --print-xml > dc01.xml

# QEMU user networking (slirp) with localhost-only forwards and restrict=on, so the guest
# cannot open connections anywhere. libvirt's passt backend would be the native way, but
# Ubuntu 24.04's AppArmor profile blocks QEMU from reaching the passt socket.
python3 - <<'EOF'
p = "dc01.xml"; s = open(p).read()
fw = [("tcp", 12222, 22), ("tcp", 10389, 389), ("udp", 10389, 389), ("tcp", 10636, 636),
      ("tcp", 13268, 3268), ("tcp", 13269, 3269), ("tcp", 10088, 88), ("udp", 10088, 88),
      ("tcp", 10445, 445), ("tcp", 10053, 53), ("udp", 10053, 53), ("tcp", 15985, 5985)]
net = "user,id=adlab0,restrict=on," + ",".join(f"hostfwd={p}:127.0.0.1:{h}-:{g}" for p, h, g in fw)
args = ["-netdev", net, "-device", "e1000e,netdev=adlab0,bus=pcie.0,addr=0x10"]
cl = "".join(f'<qemu:arg value="{a}"/>' for a in args)
s = s.replace("<domain type=\"kvm\">",
              '<domain type="kvm" xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0">', 1)
s = s.replace("</domain>", f"<qemu:commandline>{cl}</qemu:commandline></domain>", 1)
open(p, "w").write(s)
EOF
virsh -c qemu:///system define dc01.xml
virsh -c qemu:///system start adlab-dc01

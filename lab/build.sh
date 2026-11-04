#!/usr/bin/env bash
# Build the adlab DC VM (Windows Server 2025 eval) on this host.
# Only localhost ports are forwarded to the guest; it has no address on any host network.
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

# passt user networking with localhost-only forwards (ports < 1024 need root on the host side)
python3 - <<'EOF'
import re
p = "dc01.xml"; s = open(p).read()
fw = [("tcp", 12222, 22), ("tcp", 10389, 389), ("udp", 10389, 389), ("tcp", 10636, 636),
      ("tcp", 13268, 3268), ("tcp", 13269, 3269), ("tcp", 10088, 88), ("udp", 10088, 88),
      ("tcp", 10445, 445), ("tcp", 10053, 53), ("udp", 10053, 53), ("tcp", 15985, 5985)]
by = {}
for proto, host, guest in fw:
    by.setdefault(proto, []).append(f'<range start="{host}" to="{guest}"/>')
pf = "".join(f'<portForward proto="{k}" address="127.0.0.1">{"".join(v)}</portForward>' for k, v in by.items())
nic = f'<interface type="user"><backend type="passt"/><model type="e1000e"/>{pf}</interface>'
s = s.replace("</devices>", nic + "</devices>", 1)
open(p, "w").write(s)
EOF
virsh -c qemu:///system define dc01.xml
virsh -c qemu:///system start adlab-dc01

#!/usr/bin/env bash
# Run this ON THE TARGET NODE (target-node01, Oracle Linux 8, A1/6GB).
# Installs ONLY what a scanned/patched server needs: the scanner + a sample app.
# NO agent code, NO LLM SDKs, NO Ansible here - the target stays minimal.
set -euo pipefail

# Sample app for the smoke test
sudo dnf install -y nginx
echo ok | sudo tee /usr/share/nginx/html/health >/dev/null
sudo systemctl enable --now nginx

# Trivy via its RPM repo (more robust than the install script on PATH quirks)
cat <<'EOF' | sudo tee /etc/yum.repos.d/trivy.repo >/dev/null
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/8/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
sudo dnf install -y trivy

trivy --version
python3 --version          # Ansible (run from the control node) uses this over SSH

echo
echo "Target node ready. Optional: plant a test vulnerability so agents have work:"
echo "  sudo dnf install -y --allowerasing sudo-1.8.29-6.el8   # older, vulnerable"
echo "Then confirm findings exist:"
echo "  sudo trivy rootfs --scanners vuln --pkg-types os --severity HIGH,CRITICAL --timeout 15m /"

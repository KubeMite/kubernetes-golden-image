#!/bin/bash

echo 'Running pre-destroy Kubernetes cleanup'

export KUBECONFIG=/etc/kubernetes/admin.conf

# Check if cluster is running. If not, skip cleanup.
if ! timeout 20 kubectl cluster-info &> /dev/null; then
  echo 'Kubernetes API server not reachable. Skipping cleanup'
  exit 0
fi

mapfile -t all_namespaces < <(kubectl get ns --no-headers -o custom-columns=":metadata.name")
namespaces_to_not_delete=("kube-node-lease" "kube-public" "kube-system" "csi" "cilium-secrets" "default")
filtered_namespaces=()

# Remove system namespaces from the list
for item in "${all_namespaces[@]}"; do
  if [[ " ${namespaces_to_not_delete[*]} " != *" $item "* ]]; then
    filtered_namespaces+=("$item")
  fi
done

for item in "${filtered_namespaces[@]}"; do
  kubectl delete ns "$item" --cascade='foreground' --grace-period=120 --timeout=200s --wait
done

# Wait for CSI to delete Proxmox virtual disks
sleep 30

echo 'Kubernetes cleanup complete. Proceeding with VM destruction'
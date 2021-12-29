# kubeadm-vagrant

Run kubernetes cluster with kubeadm on vagrant.

> **Reference:** [Creating Highly Available clusters with kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/)

## Requirements

1. virtualbox: [https://www.virtualbox.org/wiki/Downloads](https://www.virtualbox.org/wiki/Downloads)
2. vagrant: [https://www.vagrantup.com/downloads.html](https://www.vagrantup.com/downloads.html)

## Usage

### Single-Master

Change `MASTER_COUNT` to `1` to run a Single-Master.

```bash
vagrant up master1 worker1
vagrant ssh master1

kubectl cluster-info
kubectl get nodes
```

### Multi-Master

Change `MASTER_COUNT` to `3` to run a Multi-Master cluster.

```bash
vagrant up master1 master2 master3 worker1
vagrant ssh master1

kubectl cluster-info
kubectl get nodes
```

## Pod Network

> **Reference:** [Installing a Pod network add-on](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/#pod-network)

### calico

Change `POD_NETWORK` to `/vagrant/kube-calico.yaml` to run use calico. See origin [calico.yaml](https://docs.projectcalico.org/manifests/calico.yaml)

`kube-calico.yml` changes: explicitly assign env `CALICO_IPV4POOL_CIDR` and `IP_AUTODETECTION_METHOD`

### flannel

Change `POD_NETWORK` to `/vagrant/kube-flannel.yml` to run use flannel. See origin [kube-flannel.yml](https://github.com/flannel-io/flannel/blob/master/Documentation/kube-flannel.yml)

`kube-flannel.yml` changes: added the `--iface` option ([ref](https://github.com/coreos/flannel/blob/master/Documentation/troubleshooting.md#vagrant))

## Ref

- [https://github.com/tsl0922/kubeadm-vagrant](https://github.com/tsl0922/kubeadm-vagrant)
- [https://github.com/coolsvap/kubeadm-vagrant](https://github.com/coolsvap/kubeadm-vagrant)
- [https://github.com/hub-kubernetes/kubernetes-multi-master](https://github.com/hub-kubernetes/kubernetes-multi-master)
- [https://github.com/luckylucky421/kubernetes1.17.3](https://github.com/luckylucky421/kubernetes1.17.3)

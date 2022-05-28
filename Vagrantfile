BOX_IMAGE    = "ubuntu/focal64"
MASTER_COUNT = 1
WORKER_COUNT = 3
LOAD_BALANCER_IP    = "192.168.26.10"
LOAD_BALANCER_PORT  = "8443"
NODE_INTERFACE = "enp0s8"
NODE_IP_NW   = "192.168.26."
POD_NW_CIDR  = "10.244.0.0/16"
SVC_NW_CIDR  = "10.96.0.0/12"

DOCKER_VER = "20.10.16"
KUBE_VER   = "1.21.9"
CONTAINERD_VER = "1.5.8"
BUILDKIT_VER = "0.9.3"
CRIO_VER = "1.21.4"
NERDCTL_VER = "0.13.0"
HELM_VER = "3.7.2"
KUBE_TOKEN = "ayngk7.m1555duk5x2i3ctt"
IMAGE_REPO = "registry.aliyuncs.com/google_containers"
#IMAGE_REPO = "k8s.gcr.io"
DNS_IMAGE_REPO = "docker.io/dyrnq"
POD_NETWORK = "/vagrant/kube-calico.yaml"
#POD_NETWORK = "/vagrant/kube-flannel.yml"
CURL_EXTRA_ARGS = ""
def gen_haproxy_backend(master_count)
  server=""
  (1..master_count).each do |i|
    ip = NODE_IP_NW + "#{i + 10}"
    server << "    server apiserver#{i} #{ip}:6443 check\n"
  end
  server
end

init_script = <<SCRIPT
#!/usr/bin/env bash

set -eo pipefail

echo "root:vagrant" | sudo chpasswd
timedatectl set-timezone "Asia/Shanghai"
# timedatectl set-local-rtc no
# timedatectl set-ntp off

sed -i "s@http://.*archive.ubuntu.com@http://mirrors.ustc.edu.cn@g" /etc/apt/sources.list && \
sed -i "s@http://.*security.ubuntu.com@http://mirrors.ustc.edu.cn@g" /etc/apt/sources.list;
apt update;
DEBIAN_FRONTEND=noninteractive apt -y upgrade;
DEBIAN_FRONTEND=noninteractive apt install -y apt-transport-https ca-certificates curl net-tools jq make wget ipvsadm conntrack;

cat > /etc/sysctl.d/k8s.conf <<EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_nonlocal_bind = 1
net.ipv4.ip_forward = 1
vm.swappiness=0
# https://github.com/moby/moby/issues/31208
# ipvsadm -l --timeout
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 10
EOF
sysctl --system

cat > /etc/modules-load.d/90-net.conf<<EOF
overlay
br_netfilter
EOF

systemctl daemon-reload
systemctl enable systemd-modules-load.service && systemctl restart systemd-modules-load.service

# retry three times
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 8B57C5C2836F4BEB || \
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 8B57C5C2836F4BEB || \
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 8B57C5C2836F4BEB

curl -s https://repo.huaweicloud.com/kubernetes/apt/doc/apt-key.gpg | apt-key add -
cat > /etc/apt/sources.list.d/kubernetes.list <<EOF
deb https://mirrors.tuna.tsinghua.edu.cn/kubernetes/apt kubernetes-xenial main
EOF
apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y kubelet=#{KUBE_VER}-00 kubeadm=#{KUBE_VER}-00 kubectl=#{KUBE_VER}-00


ip4=\$(ip -o -4 addr list #{NODE_INTERFACE} | head -n1 | awk '{print \$4}' |cut -d/ -f1);
cat > /etc/default/kubelet <<EOF
KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=\${ip4}
EOF

systemctl daemon-reload
systemctl enable kubelet && systemctl restart kubelet

curl #{CURL_EXTRA_ARGS} --retry 3 -SL --compressed --progress-bar -o /tmp/helm.tar.gz https://get.helm.sh/helm-v#{HELM_VER}-linux-amd64.tar.gz
tar -xv --wildcards -C /usr/bin --strip-components=1 -f /tmp/helm.tar.gz */helm

cat <<EOF | tee -a /etc/multipath.conf
blacklist {
  device {
    vendor "VBOX"
    product "HARDDISK"
  }
}
EOF
systemctl restart multipathd

SCRIPT

install_docker = <<SCRIPT
#!/usr/bin/env bash

groupadd docker
usermod -aG docker vagrant
curl -fsSL https://ghproxy.com/https://raw.githubusercontent.com/dyrnq/install-docker/main/install-docker.sh | bash -s docker --mirror tencent --systemd-mirror ghproxy --version #{DOCKER_VER}
sed -i "s@\\"live-restore\\"@\\"exec-opts\\": [\\"native.cgroupdriver=systemd\\"], \\"live-restore\\"@" /etc/docker/daemon.json
mkdir -p /etc/systemd/system/docker.service.d

systemctl daemon-reload
systemctl enable docker && systemctl restart docker

SCRIPT


install_containerd = <<SCRIPT
#!/usr/bin/env bash

curl #{CURL_EXTRA_ARGS} --retry 3 -o /tmp/cri-containerd-cni-#{CONTAINERD_VER}-linux-amd64.tar.gz -SL --compressed --progress-bar https://github.com/containerd/containerd/releases/download/v#{CONTAINERD_VER}/cri-containerd-cni-#{CONTAINERD_VER}-linux-amd64.tar.gz

tar -xv -C / -f /tmp/cri-containerd-cni-#{CONTAINERD_VER}-linux-amd64.tar.gz

# https://kubernetes.io/docs/setup/production-environment/container-runtimes/#containerd-systemd
mkdir -p /etc/containerd
containerd config default | tee /etc/containerd/config.toml
sed -i "s@SystemdCgroup = false@SystemdCgroup = true@g" /etc/containerd/config.toml
sed -i "s@k8s.gcr.io\/pause@registry.aliyuncs.com/google_containers\/pause@g" /etc/containerd/config.toml

keyline=\$(cat /etc/containerd/config.toml | grep -n "grpc" | head -1 | cut -d ":" -f 1)
sed -i "\${keyline},28s|gid = 0|gid = 5000|" /etc/containerd/config.toml

if [ -f /etc/cni/net.d/10-containerd-net.conflist ]; then
  rm -rf /etc/cni/net.d/10-containerd-net.conflist;
fi

curl #{CURL_EXTRA_ARGS} -fsSL https://github.com/containerd/nerdctl/releases/download/v#{NERDCTL_VER}/nerdctl-#{NERDCTL_VER}-linux-amd64.tar.gz |tar xvz -C /usr/local/bin nerdctl

curl #{CURL_EXTRA_ARGS} --retry 3 -o /tmp/buildkit-v#{BUILDKIT_VER}.linux-amd64.tar.gz -fsSL https://github.com/moby/buildkit/releases/download/v#{BUILDKIT_VER}/buildkit-v#{BUILDKIT_VER}.linux-amd64.tar.gz

tar -xv --strip-components 1 -C /usr/local/bin/ -f /tmp/buildkit-v#{BUILDKIT_VER}.linux-amd64.tar.gz

cat > /usr/lib/systemd/system/buildkit.service << EOF
[Unit]
Description=BuildKit
Requires=buildkit.socket
After=buildkit.socket
Documentation=https://github.com/moby/buildkit

[Service]
ExecStart=/usr/local/bin/buildkitd --addr fd:// --containerd-worker=true --oci-worker=false

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/lib/systemd/system/buildkit.socket <<EOF
[Unit]
Description=BuildKit
Documentation=https://github.com/moby/buildkit

[Socket]
ListenStream=%t/buildkit/buildkitd.sock
SocketMode=0660
SocketUser=root
SocketGroup=docker

[Install]
WantedBy=sockets.target
EOF


groupadd --gid 5000 docker >/dev/null 2>&1  || true
usermod -aG docker vagrant

systemctl daemon-reload
systemctl enable containerd && systemctl restart containerd
systemctl enable buildkit && systemctl restart buildkit
ctr ns c k8s.io || true

SCRIPT

install_crio = <<SCRIPT
#!/usr/bin/env bash
criourl="https://storage.googleapis.com/k8s-conform-cri-o/artifacts/cri-o.amd64.v#{CRIO_VER}.tar.gz"
criourl=$(curl -fsSL https://api.github.com/repos/cri-o/cri-o/releases/tags/v#{CRIO_VER} | jq '.body' | grep -oP "https[^ ]*\.gz" | grep amd64)

curl #{CURL_EXTRA_ARGS} --retry 3 -o /tmp/cri-o.amd64.v#{CRIO_VER}.tar.gz -SL --compressed --progress-bar $criourl

tar -xv -C /tmp -f /tmp/cri-o.amd64.v#{CRIO_VER}.tar.gz

pushd /tmp/cri-o > /dev/null || exit
ls -l .
if [ -f install ]; then
  bash install
else
  make install
fi
popd > /dev/null || exit

cat /dev/null > /etc/crio/crio.conf

mkdir -p /etc/crio/crio.conf.d/
cat > /etc/crio/crio.conf.d/01-pause-image.conf <<EOF
[crio.image]
pause_image = "registry.aliyuncs.com/google_containers/pause:3.5"
EOF

cat > /etc/containers/registries.conf <<EOF
unqualified-search-registries = ["docker.io","quay.io"]

[[registry]]
prefix = "docker.io"
location = "docker.io"

[[registry.mirror]]
prefix = "docker.io"
location = "docker.mirrors.ustc.edu.cn"

EOF

if [ -f /etc/cni/net.d/10-crio-bridge.conf ]; then
  rm -rf /etc/cni/net.d/10-crio-bridge.conf;
fi

systemctl daemon-reload
systemctl enable crio && systemctl restart crio

SCRIPT

worker_script = <<SCRIPT
#!/usr/bin/env bash

set -eo pipefail


discovery_token_ca_cert_hash="$(grep 'discovery-token-ca-cert-hash' /vagrant/kubeadm.log | head -n1 | awk '{print $2}')"
print_join_apiserver="$(grep 'kubeadm join' /vagrant/kubeadm.log  |head -n1 |awk '{print $3}')"
kubeadm reset -f
kubeadm join ${print_join_apiserver} --token #{KUBE_TOKEN} --discovery-token-ca-cert-hash ${discovery_token_ca_cert_hash}
SCRIPT

single_master_script = <<SCRIPT
#!/usr/bin/env bash

set -eo pipefail


kubeadm reset -f

mkdir -p /etc/kubernetes/pki/etcd
pushd /etc/kubernetes/pki > /dev/null || exit
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -sha512 -subj "/CN=kubernetes-ca" -key ca.key -out ca.crt -days 73000
openssl genrsa -out front-proxy-ca.key 4096
openssl req -x509 -new -nodes -sha512 -subj "/CN=front-proxy-ca" -key front-proxy-ca.key -out front-proxy-ca.crt -days 73000
openssl genrsa -out etcd/ca.key 4096
openssl req -x509 -new -nodes -sha512 -subj "/CN=etcd-ca" -key etcd/ca.key -out etcd/ca.crt -days 73000
popd > /dev/null || exit
ls -l /etc/kubernetes/pki


ip4=\$(ip -o -4 addr list #{NODE_INTERFACE} | head -n1 | awk '{print \$4}' |cut -d/ -f1);

cat > /tmp/kubeadm-config.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta2
kind: InitConfiguration
bootstrapTokens:
- token: #{KUBE_TOKEN}
  ttl: 0h
localAPIEndpoint:
  advertiseAddress: ${ip4}
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
kubernetesVersion: v#{KUBE_VER}
imageRepository: #{IMAGE_REPO}
networking:
  podSubnet: #{POD_NW_CIDR}
  serviceSubnet: #{SVC_NW_CIDR}
dns:
  imageRepository: #{DNS_IMAGE_REPO}
controllerManager:
  extraArgs:
    cluster-signing-duration: 438000h
    v: "4"
scheduler:
  extraArgs:
    v: "4"
apiServer:
  extraArgs:
    v: "4"
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: "ipvs"
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
failSwapOn: false
serverTLSBootstrap: true
evictionHard:
  memory.available: "200Mi"
clusterDNS:
  - 10.96.0.10
EOF

#controlPlaneEndpoint: "#{LOAD_BALANCER_IP}:#{LOAD_BALANCER_PORT}"
kubeadm init --config=/tmp/kubeadm-config.yaml | tee /vagrant/kubeadm.log

mkdir -p $HOME/.kube
sudo cp -Rf /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

mkdir -p /home/vagrant/.kube
sudo cp -Rf /etc/kubernetes/admin.conf /home/vagrant/.kube/config
sudo chown -R vagrant:vagrant /home/vagrant/.kube/

kubectl apply -f #{POD_NETWORK}
SCRIPT

multi_master_script = <<SCRIPT
#!/usr/bin/env bash

set -eo pipefail

status() {
    echo -e "\033[33m >>>   $*\033[0;39m"
}

status "configuring haproxy and keepalived.."
apt-get install -y keepalived haproxy

systemctl stop keepalived || true

ip4=\$(ip -o -4 addr list #{NODE_INTERFACE} | head -n1 | awk '{print \$4}' |cut -d/ -f1);

vrrp_state="BACKUP"
vrrp_priority="100"
if [ "${ip4}" = "#{NODE_IP_NW}11" ]; then
  vrrp_state="MASTER"
  vrrp_priority="101"
fi

cat > /etc/keepalived/keepalived.conf <<EOF
global_defs {
    router_id LVS_DEVEL
}
vrrp_script check_apiserver {
    script "/etc/keepalived/check_apiserver.sh"
    interval 2
    weight -5
    fall 3
    rise 2
}
vrrp_instance VI_1 {
    state ${vrrp_state}
    interface #{NODE_INTERFACE}
    mcast_src_ip ${ip4}
    virtual_router_id 51
    priority ${vrrp_priority}
    advert_int 2
    authentication {
        auth_type PASS
        auth_pass a6E/CHhJkCn1Ww1gF3qPiJTKTEc=
    }
    virtual_ipaddress {
        #{LOAD_BALANCER_IP}
    }
    track_script {
       check_apiserver
    }
}
EOF

cat > /etc/keepalived/check_apiserver.sh <<EOF
#!/usr/bin/env bash

errorExit() {
  echo "*** $*" 1>&2
  exit 1
}

curl --silent --max-time 2 --insecure https://localhost:6443/ -o /dev/null || errorExit "Error GET https://localhost:6443/"
if ip addr | grep -q #{LOAD_BALANCER_IP}; then
  curl --silent --max-time 2 --insecure https://#{LOAD_BALANCER_IP}:#{LOAD_BALANCER_PORT}/ -o /dev/null || errorExit "Error GET https://#{LOAD_BALANCER_IP}:#{LOAD_BALANCER_PORT}/"
fi
EOF

systemctl restart keepalived
sleep 10

cat > /etc/haproxy/haproxy.cfg <<EOF
global
  log /dev/log  local0
  log /dev/log  local1 notice
  chroot /var/lib/haproxy
  user haproxy
  group haproxy
  daemon

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5s
    timeout client 50s
    timeout client-fin 50s
    timeout server 50s
    timeout tunnel 1h

listen stats
    bind *:1080
    stats refresh 30s
    stats uri /stats

listen kube-api-server
    bind #{LOAD_BALANCER_IP}:#{LOAD_BALANCER_PORT}
    mode tcp
    option tcplog
    balance roundrobin

#{gen_haproxy_backend(MASTER_COUNT)}
EOF

systemctl restart haproxy

if [ ${vrrp_state} = "MASTER" ]; then
  cat > /tmp/kubeadm-config.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta2
kind: InitConfiguration
bootstrapTokens:
- token: #{KUBE_TOKEN}
  ttl: 0h
localAPIEndpoint:
  advertiseAddress: ${ip4}
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
kubernetesVersion: v#{KUBE_VER}
controlPlaneEndpoint: "#{LOAD_BALANCER_IP}:#{LOAD_BALANCER_PORT}"
imageRepository: #{IMAGE_REPO}
networking:
  podSubnet: #{POD_NW_CIDR}
  serviceSubnet: #{SVC_NW_CIDR}
dns:
  imageRepository: #{DNS_IMAGE_REPO}
controllerManager:
  extraArgs:
    cluster-signing-duration: 438000h
    v: "4"
scheduler:
  extraArgs:
    v: "4"
apiServer:
  extraArgs:
    v: "4"
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: "ipvs"
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
failSwapOn: false
serverTLSBootstrap: true
evictionHard:
  memory.available: "200Mi"
clusterDNS:
  - 10.96.0.10
EOF

  status "running kubeadm init on the first master node.."
  kubeadm reset -f

  mkdir -p /etc/kubernetes/pki/etcd
  pushd /etc/kubernetes/pki > /dev/null || exit
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -nodes -sha512 -subj "/CN=kubernetes-ca" -key ca.key -out ca.crt -days 73000
  openssl genrsa -out front-proxy-ca.key 4096
  openssl req -x509 -new -nodes -sha512 -subj "/CN=front-proxy-ca" -key front-proxy-ca.key -out front-proxy-ca.crt -days 73000
  openssl genrsa -out etcd/ca.key 4096
  openssl req -x509 -new -nodes -sha512 -subj "/CN=etcd-ca" -key etcd/ca.key -out etcd/ca.crt -days 73000
  popd > /dev/null || exit
  ls -l /etc/kubernetes/pki

  kubeadm init --config=/tmp/kubeadm-config.yaml --upload-certs | tee /vagrant/kubeadm.log

  mkdir -p $HOME/.kube
  sudo cp -Rf /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

  mkdir -p /home/vagrant/.kube
  sudo cp -Rf /etc/kubernetes/admin.conf /home/vagrant/.kube/config
  sudo chown -R vagrant:vagrant /home/vagrant/.kube/
  
  status "installing flannel network addon.."
  kubectl apply -f #{POD_NETWORK}
else
  status "joining master node.."
  discovery_token_ca_cert_hash="$(grep 'discovery-token-ca-cert-hash' /vagrant/kubeadm.log | head -n1 | awk '{print $2}')"
  certificate_key="$(grep 'certificate-key' /vagrant/kubeadm.log | head -n1 | awk '{print $3}')"
  kubeadm reset -f
  kubeadm join #{LOAD_BALANCER_IP}:#{LOAD_BALANCER_PORT} --token #{KUBE_TOKEN} \
    --discovery-token-ca-cert-hash ${discovery_token_ca_cert_hash} \
    --control-plane --certificate-key ${certificate_key} \
    --apiserver-advertise-address ${ip4}
fi
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = BOX_IMAGE
  config.vm.box_check_update = false

  config.vm.provision :shell, inline: init_script

  # config.hostmanager.enabled = true
  # config.hostmanager.manage_guest = true

  (1..MASTER_COUNT).each do |i|
    ha = MASTER_COUNT > 1
    hostname= "master#{i}"
    config.vm.define(hostname) do |subconfig|
      subconfig.vm.hostname = hostname
      subconfig.vm.network :private_network, nic_type: "virtio", ip: NODE_IP_NW + "#{i + 10}"
      subconfig.vm.provider :virtualbox do |vb|
        vb.customize ["modifyvm", :id, "--ioapic", "on"]
        vb.customize ["modifyvm", :id, "--cpus", "2"]
        vb.customize ["modifyvm", :id, "--memory", "2048"]
      end
      subconfig.vm.provision :shell, inline: install_docker
      subconfig.vm.provision :shell, inline: ha ? multi_master_script : single_master_script
    end
  end

  (1..WORKER_COUNT).each do |i|
    hostname= "worker#{i}"
    config.vm.define(hostname) do |subconfig|
      subconfig.vm.hostname = hostname
      subconfig.vm.network :private_network, nic_type: "virtio", ip: NODE_IP_NW + "#{i + 20}"
      if i == 1
        subconfig.vm.provision :shell, inline: install_docker
      elsif i == 2
        subconfig.vm.provision :shell, inline: install_containerd
      elsif i == 3
        subconfig.vm.provision :shell, inline: install_crio
      else
        subconfig.vm.provision :shell, inline: install_docker
      end
      subconfig.vm.provision :shell, inline: worker_script
    end
  end
end

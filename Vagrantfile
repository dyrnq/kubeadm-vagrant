BOX_IMAGE    = "ubuntu/focal64"
MASTER_COUNT = 1
WORKER_COUNT = 2
MASTER_IP    = "192.168.26.10"
MASTER_PORT  = "8443"
NODE_IP_NW   = "192.168.26."
POD_NW_CIDR  = "10.244.0.0/16"

DOCKER_VER = "5:19.03.4~3-0~ubuntu-xenial"
KUBE_VER   = "1.21.2"
KUBE_TOKEN = "ayngk7.m1555duk5x2i3ctt"
IMAGE_REPO = "registry.aliyuncs.com/google_containers"
#IMAGE_REPO = "k8s.gcr.io"
POD_NETWORK = "/vagrant/kube-calico.yaml"
#POD_NETWORK = "/vagrant/kube-flannel.yml"

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
groupadd docker
usermod -aG docker vagrant
timedatectl set-timezone "Asia/Shanghai"
# timedatectl set-local-rtc no
# timedatectl set-ntp off

sed -i "s@http://.*archive.ubuntu.com@http://repo.huaweicloud.com@g" /etc/apt/sources.list && \
sed -i "s@http://.*security.ubuntu.com@http://repo.huaweicloud.com@g" /etc/apt/sources.list;
apt update;
DEBIAN_FRONTEND=noninteractive apt -y upgrade;
DEBIAN_FRONTEND=noninteractive apt install -y apt-transport-https ca-certificates curl net-tools jq;

cat > /etc/sysctl.d/k8s.conf <<EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_nonlocal_bind = 1
net.ipv4.ip_forward = 1
vm.swappiness=0
EOF
sysctl --system

curl -fsSL https://ghproxy.com/https://raw.githubusercontent.com/dyrnq/install-docker/main/install-docker.sh | bash -s docker --mirror huaweicloud --version 20.10.7

# retry 3 times
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 8B57C5C2836F4BEB || \
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 8B57C5C2836F4BEB || \
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 8B57C5C2836F4BEB

curl -s https://repo.huaweicloud.com/kubernetes/apt/doc/apt-key.gpg | apt-key add -
cat > /etc/apt/sources.list.d/kubernetes.list <<EOF
deb https://mirrors.tuna.tsinghua.edu.cn/kubernetes/apt kubernetes-xenial main
EOF
apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y kubelet=#{KUBE_VER}-00 kubeadm=#{KUBE_VER}-00 kubectl=#{KUBE_VER}-00


sed -i "s@\\"live-restore\\"@\\"exec-opts\\": [\\"native.cgroupdriver=systemd\\"], \\"live-restore\\"@" /etc/docker/daemon.json

mkdir -p /etc/systemd/system/docker.service.d

# https://github.com/kubernetes/kubernetes/issues/45487
# echo 'User=root' >> /etc/systemd/system/kubelet.service.d/10-kubeadm.conf


ip4=\$(ip -o -4 addr list enp0s8 | head -n1 | awk '{print \$4}' |cut -d/ -f1);
cat > /etc/default/kubelet <<EOF
KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=\${ip4}
EOF


systemctl daemon-reload
systemctl enable kubelet && systemctl restart kubelet
systemctl enable docker && systemctl restart docker

docker pull registry.aliyuncs.com/google_containers/coredns:1.8.0
docker tag registry.aliyuncs.com/google_containers/coredns:1.8.0 registry.aliyuncs.com/google_containers/coredns:v1.8.0

SCRIPT

worker_script = <<SCRIPT
#!/usr/bin/env bash

set -eo pipefail

apt-get install -y ipvsadm

discovery_token_ca_cert_hash="$(grep 'discovery-token-ca-cert-hash' /vagrant/kubeadm.log | head -n1 | awk '{print $2}')"
print_join_apiserver="$(grep 'kubeadm join' /vagrant/kubeadm.log  |head -n1 |awk '{print $3}')"
kubeadm reset -f
kubeadm join ${print_join_apiserver} --token #{KUBE_TOKEN} --discovery-token-ca-cert-hash ${discovery_token_ca_cert_hash}
SCRIPT

single_master_script = <<SCRIPT
#!/usr/bin/env bash

set -eo pipefail

apt-get install -y ipvsadm

kubeadm reset -f

mkdir -p /etc/kubernetes/pki/etcd
cd /etc/kubernetes/pki
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -sha512 -subj "/CN=kubernetes-ca" -key ca.key -out ca.crt -days 73000
openssl genrsa -out front-proxy-ca.key 4096
openssl req -x509 -new -nodes -sha512 -subj "/CN=front-proxy-ca" -key front-proxy-ca.key -out front-proxy-ca.crt -days 73000
openssl genrsa -out etcd/ca.key 4096
openssl req -x509 -new -nodes -sha512 -subj "/CN=etcd-ca" -key etcd/ca.key -out etcd/ca.crt -days 73000
ls -l /etc/kubernetes/pki

ip4=\$(ip -o -4 addr list enp0s8 | head -n1 | awk '{print \$4}' |cut -d/ -f1);

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
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: "ipvs"
EOF

#controlPlaneEndpoint: "#{MASTER_IP}:#{MASTER_PORT}"
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
apt-get install -y keepalived haproxy ipvsadm

systemctl stop keepalived || true

vrrp_if=$(ip a | grep 192.168.26 | awk '{print $7}')
vrrp_ip=$(ip a | grep 192.168.26 | awk '{split($2, a, "/"); print a[1]}')
vrrp_state="BACKUP"
vrrp_priority="100"
if [ "${vrrp_ip}" = "#{NODE_IP_NW}11" ]; then
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
    interface ${vrrp_if}
    mcast_src_ip ${vrrp_ip}
    virtual_router_id 51
    priority ${vrrp_priority}
    advert_int 2
    authentication {
        auth_type PASS
        auth_pass a6E/CHhJkCn1Ww1gF3qPiJTKTEc=
    }
    virtual_ipaddress {
        #{MASTER_IP}
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
if ip addr | grep -q #{MASTER_IP}; then
  curl --silent --max-time 2 --insecure https://#{MASTER_IP}:#{MASTER_PORT}/ -o /dev/null || errorExit "Error GET https://#{MASTER_IP}:#{MASTER_PORT}/"
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
    bind #{MASTER_IP}:#{MASTER_PORT}
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
  ttl: 24h
localAPIEndpoint:
  advertiseAddress: ${vrrp_ip}
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
kubernetesVersion: v#{KUBE_VER}
controlPlaneEndpoint: "#{MASTER_IP}:#{MASTER_PORT}"
imageRepository: #{IMAGE_REPO}
networking:
  podSubnet: #{POD_NW_CIDR}
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: "ipvs"
EOF

  status "running kubeadm init on the first master node.."
  kubeadm reset -f

  mkdir -p /etc/kubernetes/pki/etcd
  cd /etc/kubernetes/pki
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -nodes -sha512 -subj "/CN=kubernetes-ca" -key ca.key -out ca.crt -days 73000
  openssl genrsa -out front-proxy-ca.key 4096
  openssl req -x509 -new -nodes -sha512 -subj "/CN=front-proxy-ca" -key front-proxy-ca.key -out front-proxy-ca.crt -days 73000
  openssl genrsa -out etcd/ca.key 4096
  openssl req -x509 -new -nodes -sha512 -subj "/CN=etcd-ca" -key etcd/ca.key -out etcd/ca.crt -days 73000
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
  kubeadm join #{MASTER_IP}:#{MASTER_PORT} --token #{KUBE_TOKEN} \
    --discovery-token-ca-cert-hash ${discovery_token_ca_cert_hash} \
    --control-plane --certificate-key ${certificate_key} \
    --apiserver-advertise-address ${vrrp_ip}
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
      subconfig.vm.provision :shell, inline: ha ? multi_master_script : single_master_script
    end
  end

  (1..WORKER_COUNT).each do |i|
    hostname= "worker#{i}"
    config.vm.define(hostname) do |subconfig|
      subconfig.vm.hostname = hostname
      subconfig.vm.network :private_network, nic_type: "virtio", ip: NODE_IP_NW + "#{i + 20}"
      subconfig.vm.provision :shell, inline: worker_script
    end
  end
end

#!/bin/bash

# Update package lists
sudo apt update

# Upgrade installed packages without user prompt
sudo apt upgrade -y

# Install k3s using the official installer script
sudo curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644" sh -

# Check the status of k3s service
sudo systemctl status k3s

# Download and install node_exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.5.0/node_exporter-1.5.0.linux-amd64.tar.gz
tar -xvzf node_exporter-*.tar.gz
sudo mv node_exporter-1.5.0.linux-amd64/node_exporter /usr/local/bin
rm -r node_exporter-1.5.0.linux-amd64*

# Create a system user for node_exporter
sudo useradd -rs /bin/false node_exporter

# Insert node_exporter systemd service unit
sudo tee /etc/systemd/system/node_exporter.service > /dev/null <<EOT
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOT

# Enable and start node_exporter service
sudo systemctl enable node_exporter
sudo systemctl daemon-reload
sudo systemctl start node_exporter
sudo systemctl status node_exporter

# Clone the repository containing Kubernetes files
sudo git clone https://github.com/shreyashettys202/DevOps2023-2024-Group3.git /home/ubuntu/DevOps2023-2024-Group3

# Navigate to the cloned repository directory
cd /home/ubuntu/DevOps2023-2024-Group3

# Change the ownership of the directory to the current user
sudo chown -R $USER:$USER .

# Switch to the 'develop' branch
git checkout develop

# Navigate to the directory containing Kubernetes files
cd k8s-files

# Apply Kubernetes configurations
sudo kubectl apply -f .

# Get information about running pods
sudo kubectl get pods


# Function to get public IP of EC2 instance
get_public_ip() {
    public_ip=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
    echo "$public_ip"
}

# Step 1: Create a new user and add new directories
sudo useradd --no-create-home prometheus
sudo mkdir /etc/prometheus
sudo mkdir /var/lib/prometheus

# Step 2: Download Prometheus, extract it, and put it in /usr/local/bin folder
wget https://github.com/prometheus/prometheus/releases/download/v2.50.1/prometheus-2.50.1.linux-amd64.tar.gz
tar -xvf prometheus-2.50.1.linux-amd64.tar.gz
sudo cp prometheus-2.50.1.linux-amd64/prometheus /usr/local/bin
sudo cp prometheus-2.50.1.linux-amd64/promtool /usr/local/bin
sudo cp -r prometheus-2.50.1.linux-amd64/consoles /etc/prometheus/
sudo cp -r prometheus-2.50.1.linux-amd64/console_libraries /etc/prometheus
rm -rf prometheus-2.50.1.linux-amd64.tar.gz prometheus-2.50.1.linux-amd64

# Step 3: Configure Prometheus to monitor itself using yaml file
public_ip=$(get_public_ip)
sudo tee /etc/prometheus/prometheus.yml > /dev/null <<EOT
global:
  scrape_interval: 15s
  external_labels:
    monitor: 'prometheus'
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['$public_ip:9100']
EOT

# Step 4: Create a systemd service for Prometheus
sudo tee /etc/systemd/system/prometheus.service > /dev/null <<EOT
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file /etc/prometheus/prometheus.yml \
    --storage.tsdb.path /var/lib/prometheus/ \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
EOT

# Step 5: Change ownership of files and directories
sudo chown prometheus:prometheus /etc/prometheus
sudo chown prometheus:prometheus /usr/local/bin/prometheus
sudo chown prometheus:prometheus /usr/local/bin/promtool
sudo chown -R prometheus:prometheus /etc/prometheus/consoles
sudo chown -R prometheus:prometheus /etc/prometheus/console_libraries
sudo chown -R prometheus:prometheus /var/lib/prometheus

# Step 6: Configure the service and start it
sudo systemctl daemon-reload
sudo systemctl enable prometheus
sudo systemctl start prometheus
sudo systemctl status prometheus

# Exiting after viewing status
echo "Press 'q' to exit status view"
sudo systemctl status prometheus | less
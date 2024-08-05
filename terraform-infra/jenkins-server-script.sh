#!/bin/bash

# Update package lists
sudo apt update

# Install Java
sudo apt install -y openjdk-17-jdk

# Install Jenkins
# Install Jenkins
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
  https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
  /etc/apt/sources.list.d/jenkins.list > /dev/null
sudo apt-get update
sudo apt-get install jenkins -y
sudo systemctl start jenkins

# Install Git
sudo apt install -y git

# Install Terraform
sudo apt-get install -y gnupg software-properties-common
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install -y terraform

# Install kubectl (assuming this is done via a package manager or other method)
# Add the appropriate commands for your platform

# Check Java, Jenkins, Git, and Terraform versions
java -version
jenkins --version
git --version
terraform --version

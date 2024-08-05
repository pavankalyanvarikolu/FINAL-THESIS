data "aws_ami" "Ubuntu_20_04" {
  most_recent = true
  owners      = ["099720109477"] // Canonical account ID for Ubuntu AMIs

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "myapp-server" {
  ami                         = data.aws_ami.Ubuntu_20_04.id
  instance_type               = var.instance_type
  key_name                    = "wwa"
  subnet_id                   = aws_subnet.myapp-subnet-1.id
  vpc_security_group_ids      = [aws_default_security_group.default-sg.id]
  availability_zone           = var.avail_zone
  associate_public_ip_address = true
  user_data                   = file("k3s.sh")
  tags = {
    Name = "${var.env_prefix}-server"
  }
}
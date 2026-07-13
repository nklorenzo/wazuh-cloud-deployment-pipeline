resource "aws_key_pair" "wazuh_key" {
  key_name   = "wazuh-key"
  public_key = file("~/.ssh/wazuh-key.pub")
}

resource "aws_security_group" "ssh_only" {
  name        = "ssh-only"
  description = "autoriser uniquement le trafic SSH"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Tailscale"
    from_port   = 41641
    to_port     = 41641
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-0aba19e56f3eaec05"
  instance_type          = "m7i-flex.large"
  vpc_security_group_ids = [aws_security_group.ssh_only.id]
  key_name               = aws_key_pair.wazuh_key.key_name

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }

  tags = {
    Name = "web"
  }
}

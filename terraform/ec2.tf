# EC2 Instance
resource "aws_instance" "app" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  key_name               = var.ec2_key_name
  subnet_id              = aws_subnet.public_1.id
  vpc_security_group_ids = [aws_security_group.ec2.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              set -e

              # Update system
              dnf update -y

              # Install Python 3.11 and dependencies
              dnf install -y python3.11 python3.11-pip python3.11-devel
              dnf install -y git nginx gcc sqlite

              # Create app user
              useradd -m -s /bin/bash threatmodel

              # Create app directory
              mkdir -p /opt/threatmodel
              chown threatmodel:threatmodel /opt/threatmodel

              # Install Python packages globally for now
              pip3.11 install gunicorn

              # Configure nginx
              cat > /etc/nginx/conf.d/threatmodel.conf <<'NGINX'
              server {
                  listen 80;
                  server_name _;

                  location /static/ {
                      alias /opt/threatmodel/staticfiles/;
                  }

                  location /media/ {
                      alias /opt/threatmodel/media/;
                  }

                  location / {
                      proxy_pass http://127.0.0.1:8000;
                      proxy_set_header Host $host;
                      proxy_set_header X-Real-IP $remote_addr;
                      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                      proxy_set_header X-Forwarded-Proto $scheme;
                  }
              }
              NGINX

              # Remove default nginx config
              rm -f /etc/nginx/conf.d/default.conf

              # Start nginx
              systemctl enable nginx
              systemctl start nginx

              echo "EC2 setup complete" > /var/log/setup-complete.log
              EOF

  tags = {
    Name = "${var.project_name}-app"
  }
}

# Elastic IP for EC2
resource "aws_eip" "app" {
  instance = aws_instance.app.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-eip"
  }
}

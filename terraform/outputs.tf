# ALB Outputs (Primary Entry Point)
output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "app_url" {
  description = "Application URL"
  value       = "http://${aws_lb.main.dns_name}"
}

# RDS Outputs
output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.main.endpoint
}

output "rds_hostname" {
  description = "RDS hostname (for DB_HOST)"
  value       = aws_db_instance.main.address
}

# S3 Outputs
output "s3_bucket_name" {
  description = "S3 bucket for media and backups"
  value       = aws_s3_bucket.media.id
}

# EC2 Outputs
output "ec2_private_ip" {
  description = "Private IP of EC2 instance"
  value       = aws_instance.app.private_ip
}

# Deployment Instructions
output "deployment_instructions" {
  description = "Next steps for deployment"
  value       = <<-EOT

    =====================================================
    DEPLOYMENT INSTRUCTIONS
    =====================================================

    Application URL: http://${aws_lb.main.dns_name}

    1. SSH into the EC2 instance (requires bastion host or VPN):
       Note: EC2 instance is in private subnet at ${aws_instance.app.private_ip}
       You will need to set up a bastion host or VPN for SSH access.

    2. Clone and set up the application:
       sudo su - threatmodel
       cd /opt/threatmodel
       git clone <your-repo-url> .
       python3.11 -m venv venv
       source venv/bin/activate
       pip install -r requirements.txt
       pip install gunicorn psycopg2-binary

    3. Create .env file with:
       SECRET_KEY=<generate-a-secret-key>
       DEBUG=False
       ALLOWED_HOSTS=${aws_lb.main.dns_name}
       DB_HOST=${aws_db_instance.main.address}
       DB_NAME=${var.db_name}
       DB_USER=${var.db_username}
       DB_PASSWORD=${var.db_password}
       AWS_STORAGE_BUCKET_NAME=${aws_s3_bucket.media.id}
       AWS_S3_REGION_NAME=${var.aws_region}

    4. Run migrations and collect static:
       python manage.py migrate
       python manage.py collectstatic --noinput
       python manage.py seed_mitre
       python manage.py seed_sample_data

    5. Start gunicorn (or create a systemd service):
       gunicorn threatmodel.wsgi:application --bind 0.0.0.0:8000

    RDS Endpoint: ${aws_db_instance.main.endpoint}
    S3 Bucket: ${aws_s3_bucket.media.id}
    =====================================================
  EOT
}

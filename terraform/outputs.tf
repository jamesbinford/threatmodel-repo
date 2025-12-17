output "ec2_public_ip" {
  description = "Public IP of EC2 instance"
  value       = aws_eip.app.public_ip
}

output "ec2_public_dns" {
  description = "Public DNS of EC2 instance"
  value       = aws_eip.app.public_dns
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.main.endpoint
}

output "rds_database_name" {
  description = "RDS database name"
  value       = aws_db_instance.main.db_name
}

output "app_url" {
  description = "Application URL"
  value       = "http://${aws_eip.app.public_ip}"
}

output "ssh_command" {
  description = "SSH command to connect to EC2"
  value       = "ssh -i ~/.ssh/${var.ec2_key_name}.pem ec2-user@${aws_eip.app.public_ip}"
}

output "deployment_instructions" {
  description = "Next steps for deployment"
  value       = <<-EOT

    =====================================================
    DEPLOYMENT INSTRUCTIONS
    =====================================================

    1. SSH into the EC2 instance:
       ssh -i ~/.ssh/${var.ec2_key_name}.pem ec2-user@${aws_eip.app.public_ip}

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
       ALLOWED_HOSTS=${aws_eip.app.public_ip}
       DB_NAME=${aws_db_instance.main.db_name}
       DB_USER=${var.db_username}
       DB_PASSWORD=<your-db-password>
       DB_HOST=${aws_db_instance.main.address}
       DB_PORT=5432

    4. Run migrations and collect static:
       python manage.py migrate
       python manage.py collectstatic --noinput
       python manage.py seed_mitre
       python manage.py seed_sample_data

    5. Start gunicorn (or create a systemd service):
       gunicorn threatmodel.wsgi:application --bind 127.0.0.1:8000

    Application URL: http://${aws_eip.app.public_ip}
    =====================================================
  EOT
}

#!/bin/bash
# Deployment script for Threat Model Repository
# Run this script from the EC2 instance

set -e

APP_DIR="/opt/threatmodel"
REPO_URL="${1:-}"

echo "========================================"
echo "Threat Model Repository Deployment"
echo "========================================"

# Check if running as threatmodel user
if [ "$(whoami)" != "threatmodel" ]; then
    echo "Please run as threatmodel user: sudo su - threatmodel"
    exit 1
fi

cd $APP_DIR

# Clone or pull repository
if [ -n "$REPO_URL" ] && [ ! -d ".git" ]; then
    echo "Cloning repository..."
    git clone "$REPO_URL" .
elif [ -d ".git" ]; then
    echo "Pulling latest changes..."
    git pull
else
    echo "No .git directory and no REPO_URL provided."
    echo "Usage: ./deploy.sh <git-repo-url>"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3.11 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn

# Check for .env file
if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found!"
    echo "Create .env file with the following variables:"
    echo "  SECRET_KEY=<your-secret-key>"
    echo "  DEBUG=False"
    echo "  ALLOWED_HOSTS=<your-ec2-ip>"
    echo "  AWS_STORAGE_BUCKET_NAME=<your-s3-bucket-name>"
    echo "  AWS_S3_REGION_NAME=us-east-1"
    exit 1
fi

# Set Django settings module
export DJANGO_SETTINGS_MODULE=threatmodel.settings.production

# Create log directory
sudo mkdir -p /var/log/threatmodel
sudo chown threatmodel:threatmodel /var/log/threatmodel

# Run migrations
echo "Running migrations..."
python manage.py migrate --noinput

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Seed data if database is empty
echo "Checking if data needs to be seeded..."
python manage.py shell -c "
from apps.mitre.models import Tactic
if Tactic.objects.count() == 0:
    print('Seeding MITRE data...')
    from django.core.management import call_command
    call_command('seed_mitre')
else:
    print('MITRE data already exists')
"

# Create systemd service file
echo "Creating systemd service..."
cat > /tmp/threatmodel.service <<'EOF'
[Unit]
Description=Threat Model Repository Gunicorn Daemon
After=network.target

[Service]
User=threatmodel
Group=threatmodel
WorkingDirectory=/opt/threatmodel
Environment="PATH=/opt/threatmodel/venv/bin"
Environment="DJANGO_SETTINGS_MODULE=threatmodel.settings.production"
ExecStart=/opt/threatmodel/venv/bin/gunicorn threatmodel.wsgi:application --bind 127.0.0.1:8000 --workers 2 --timeout 120
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Create daily backup cron job
echo "Setting up daily database backup..."
mkdir -p /opt/threatmodel/backups
cat > /opt/threatmodel/backup-db.sh <<'BACKUP'
#!/bin/bash
# Daily SQLite backup to S3
set -e
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_FILE="/opt/threatmodel/db.sqlite3"
BACKUP_DIR="/opt/threatmodel/backups"
BUCKET=$(grep AWS_STORAGE_BUCKET_NAME /opt/threatmodel/.env | cut -d= -f2)

mkdir -p "$BACKUP_DIR"

if [ -f "$DB_FILE" ]; then
    # Use sqlite3 .backup for safe copy
    sqlite3 "$DB_FILE" ".backup $BACKUP_DIR/db_${TIMESTAMP}.sqlite3"

    # Upload to S3
    if [ -n "$BUCKET" ]; then
        aws s3 cp "$BACKUP_DIR/db_${TIMESTAMP}.sqlite3" "s3://${BUCKET}/backups/db_${TIMESTAMP}.sqlite3"
        echo "Backup uploaded to s3://${BUCKET}/backups/db_${TIMESTAMP}.sqlite3"
    fi

    # Keep only last 7 local backups
    ls -t "$BACKUP_DIR"/db_*.sqlite3 | tail -n +8 | xargs -r rm
fi
BACKUP

chmod +x /opt/threatmodel/backup-db.sh

# Add cron job for daily backup at 2am
(crontab -l 2>/dev/null | grep -v "backup-db.sh"; echo "0 2 * * * /opt/threatmodel/backup-db.sh >> /var/log/threatmodel/backup.log 2>&1") | crontab -

echo ""
echo "========================================"
echo "Deployment complete!"
echo "========================================"
echo ""
echo "To start the application:"
echo "  1. Copy the systemd service:"
echo "     sudo cp /tmp/threatmodel.service /etc/systemd/system/"
echo "  2. Enable and start the service:"
echo "     sudo systemctl daemon-reload"
echo "     sudo systemctl enable threatmodel"
echo "     sudo systemctl start threatmodel"
echo "  3. Check status:"
echo "     sudo systemctl status threatmodel"
echo ""
echo "Database: SQLite (local, backed up daily to S3)"
echo "Media: S3 bucket (configured via .env)"
echo ""
echo "Or run manually:"
echo "  source venv/bin/activate"
echo "  gunicorn threatmodel.wsgi:application --bind 127.0.0.1:8000"
echo ""

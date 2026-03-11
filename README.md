# Threat Model Repository

> A centralized enterprise threat modeling application for managing threat models across business units, tracking findings with STRIDE/MITRE correlation, and generating executive risk reports.

## Overview

The Threat Model Repository enables organizations to capture, organize, and analyze threat models across the entire enterprise. Rather than scattered threat assessments, this application centralizes threat data to enable leadership to make **threat-informed decisions** before design changes, software acquisitions, or architectural changes are implemented.

### Core Goals

1. **Centralize threat models** across the organization, organized by business unit with hierarchical structure
2. **Aggregate risk data** into compelling executive narratives shareable by business unit or across the firm
3. **Track trends** in risk decisions and mitigation effectiveness over time
4. **Enable CISO-level reporting** with MITRE ATT&CK and MITRE ATLAS correlation

---

## Features

- **Threat Model Management**
  - Create, edit, and publish threat models with risk ratings (1-5 scale)
  - Organize by business unit with hierarchical MPPT tree structure
  - Tag by technology for cross-functional analysis
  - Track status lifecycle (draft → published → archived)

- **Finding Management**
  - Multiple findings per threat model
  - STRIDE categorization (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
  - Inherent and residual risk tracking
  - Threat likelihood assessment (Almost Certain → Rare)
  - Owner assignment for accountability

- **MITRE Framework Integration**
  - Link findings to MITRE ATT&CK techniques (for traditional threats)
  - Link findings to MITRE ATLAS techniques (for AI/ML threats)
  - Browse and search both frameworks
  - Framework-aware reporting

- **Evidence & Documentation**
  - Multiple diagrams per threat model (Architecture, Threat Model, Other)
  - Evidence file uploads to S3 for cost-efficient storage
  - Track uploader and timestamp for audit trails
  - Mitigation recommendations as structured lists or free text

- **Organization Hierarchy**
  - Tree structure for multi-level business units
  - Efficient nested query support via MPPT
  - Aggregate risk metrics up the hierarchy

- **Executive Reporting**
  - Aggregate risk by business unit or across enterprise
  - Risk trend analysis
  - PDF export for board-level presentations

---

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Framework** | Django | 5.0+ |
| **Language** | Python | 3.10+ |
| **Database** | PostgreSQL | 16 (AWS RDS) |
| **Storage** | AWS S3 | via django-storages |
| **Load Balancer** | AWS ALB | Application Load Balancer |
| **UI Framework** | Bootstrap | 5 |
| **Forms** | Django Crispy Forms | with Bootstrap 5 integration |
| **PDF Generation** | WeasyPrint | 60.0+ |
| **Hierarchy** | django-MPPT | 0.14+ |
| **Infrastructure** | AWS EC2 + IAM | Terraform-managed |

---

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip package manager
- AWS account with S3 bucket (for production)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/threatmodel-repo.git
   cd threatmodel-repo
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings (see Configuration section)
   ```

5. **Initialize database**
   ```bash
   python manage.py migrate
   ```

6. **Create superuser**
   ```bash
   python manage.py createsuperuser
   ```

7. **Load MITRE frameworks** (optional seed commands)
   ```bash
   python manage.py load_mitre_attack
   python manage.py load_mitre_atlas
   ```

8. **Run development server**
   ```bash
   python manage.py runserver
   ```

   Access the application at `http://localhost:8000`

---

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# Django Settings
SECRET_KEY=your-django-secret-key-here
DEBUG=False
ALLOWED_HOSTS=your-alb-dns-name

# Database (RDS PostgreSQL)
DB_HOST=your-rds-endpoint.region.rds.amazonaws.com
DB_NAME=threatmodel
DB_USER=threatmodel
DB_PASSWORD=your-db-password
DB_PORT=5432

# AWS S3 Configuration
AWS_STORAGE_BUCKET_NAME=your-s3-bucket-name
AWS_S3_REGION_NAME=us-east-1
```

### Django Settings

Key application configurations in `threatmodel/settings.py`:

- **Installed Apps**: Core, Accounts, Organization, Threat Models, MITRE, Reports
- **Storage Backend**: S3 via django-storages (automatically used in production)
- **Database**: PostgreSQL via AWS RDS
- **Static Files**: Collected to S3 in production

---

## Deployment

### AWS Deployment

**Architecture Overview:**
```
Internet → ALB (public subnets) → EC2 (private subnet) → RDS PostgreSQL (database subnets)
                                         ↓
                                    S3 (media files)
```

**Infrastructure Components:**
- **VPC**: 10.0.0.0/16 with public, private, and database subnets across 2 AZs
- **ALB**: Application Load Balancer in public subnets (HTTP/HTTPS)
- **EC2**: t3.micro in private subnet (no public IP)
- **RDS**: PostgreSQL 16 on db.t3.micro with automated backups
- **S3**: Media and evidence file storage
- **NAT Gateway**: Enables EC2 outbound internet access

**Prerequisites:**
- Terraform >= 1.0
- AWS CLI configured
- EC2 key pair for SSH access

**Deployment:**
```bash
cd terraform
terraform init
terraform plan -var="ec2_key_name=your-key" -var="db_password=YourSecurePassword"
terraform apply -var="ec2_key_name=your-key" -var="db_password=YourSecurePassword"
```

**Estimated Monthly Cost:** ~$50-80 (ALB ~$16 + NAT ~$32 + EC2 t3.micro ~$8 + RDS db.t3.micro ~$13)

---

## Project Structure

```
threatmodel-repo/
├── apps/                          # Django applications
│   ├── core/                      # Dashboard, home, navigation
│   ├── accounts/                  # User authentication
│   ├── organization/              # Business unit hierarchy (MPPT)
│   ├── threatmodels/              # Core threat model, finding, diagram, evidence
│   ├── mitre/                     # ATT&CK and ATLAS framework integration
│   └── reports/                   # Executive reporting and dashboards
├── threatmodel/                   # Django project settings
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
│   └── asgi.py
├── templates/                     # HTML templates (Bootstrap 5)
├── static/                        # CSS, JavaScript assets
├── terraform/                     # AWS infrastructure as code
│   ├── main.tf                   # Provider configuration
│   ├── vpc.tf                    # VPC, subnets, NAT gateway
│   ├── alb.tf                    # Application Load Balancer
│   ├── ec2.tf                    # EC2 instance (private subnet)
│   ├── rds.tf                    # RDS PostgreSQL
│   ├── s3.tf                     # S3 bucket for media
│   ├── iam.tf                    # IAM roles and policies
│   ├── security_groups.tf        # Security groups (ALB, EC2, RDS)
│   ├── variables.tf              # Input variables
│   └── outputs.tf                # Output values
├── manage.py                      # Django management
├── requirements.txt               # Python dependencies
├── .env.example                   # Environment template
└── deploy.sh                      # Deployment automation
```

### Django Apps Overview

| App | Purpose | Key Models |
|-----|---------|-----------|
| **core** | Home dashboard, navigation | Dashboard view |
| **accounts** | User authentication and authorization | User (Django built-in) |
| **organization** | Business unit hierarchy | BusinessUnit (MPPT tree) |
| **threatmodels** | Core threat modeling | ThreatModel, Finding, Diagram, Evidence |
| **mitre** | Framework integration | MitreAttackTechnique, MitreAtlasTechnique |
| **reports** | Executive reporting | Report (aggregations) |

### Data Model Highlights

**ThreatModel**
- Title, description, overall risk rating (1-5)
- Status: draft, published, archived
- Assigned to business unit
- Technology tags for categorization

**Finding** (multiple per threat model)
- Threat ID, scenario, object
- STRIDE category (6 categories)
- Inherent and residual risk ratings
- Likelihood assessment (5 levels)
- Linked to MITRE technique
- Mitigation recommendations
- Owner assignment

**Evidence** (multiple per finding)
- File upload to S3
- Uploader and timestamp tracking
- Metadata (e.g., validation date)

**Diagram** (multiple per threat model)
- Type: Architecture, Threat Model, Other
- Stored in S3
- Description and timestamp

---

## Development

### Running Tests

```bash
python manage.py test
```

### Database Migrations

After model changes:

```bash
python manage.py makemigrations
python manage.py migrate
```

### Creating Sample Data

```bash
python manage.py shell
```

Then in the Django shell:

```python
from apps.organization.models import BusinessUnit
from apps.threatmodels.models import ThreatModel
from django.contrib.auth.models import User

# Create a business unit
bu = BusinessUnit.objects.create(name="Engineering", slug="engineering")

# Create a threat model
owner = User.objects.first()
tm = ThreatModel.objects.create(
    title="API Authentication Review",
    slug="api-auth-review",
    business_unit=bu,
    description="Threat model for REST API authentication design",
    owner=owner,
    overall_risk=3
)
```

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes and test thoroughly
3. Submit a pull request with clear description
4. Ensure tests pass and code is formatted consistently

### Code Style

- Follow PEP 8 for Python
- Use type hints where practical
- Include docstrings for models and complex functions
- Write tests for new features

---

## Support

For issues, questions, or suggestions:
- Check existing issues on GitHub
- Create a new issue with detailed description and steps to reproduce
- Contact the security team for threat modeling guidance

---

## License

This project is proprietary and confidential. Unauthorized copying or use is prohibited. 
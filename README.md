# SecureDesk – IT Support Ticket System

## Project Overview

SecureDesk is a cloud-based IT Support Ticket System developed using Python Flask and deployed on Amazon Web Services (AWS). It allows users to create and manage support tickets, upload attachments, and track ticket status. Administrators can manage users and monitor submitted tickets.

This project demonstrates the implementation of cloud hosting, application security, backup and recovery, monitoring, and DevSecOps automation.

## Live Application

**Application URL:** https://d39qz29rzn1p6r.cloudfront.net

## Technology Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Database:** Amazon RDS for MySQL
- **Web Server:** Nginx
- **Application Server:** Gunicorn
- **Cloud Platform:** Amazon Web Services (AWS)
- **Containerization:** Docker
- **CI/CD:** GitHub Actions
- **Version Control:** Git and GitHub

## Main Features

- User registration and login
- User dashboard
- Create, view, update, and manage support tickets
- Ticket attachment uploads
- Ticket status and priority management
- Administrator dashboard
- Admin user and ticket management

## AWS Architecture

The application uses the following AWS services:

- **Amazon VPC:** Provides network isolation.
- **Amazon EC2:** Hosts the application server and bastion host.
- **Application Load Balancer:** Receives and forwards application traffic.
- **Amazon CloudFront:** Provides HTTPS access to the application.
- **Amazon RDS:** Stores application data in MySQL.
- **Amazon S3:** Stores ticket attachments and backups in private buckets.
- **AWS IAM:** Controls access to AWS resources.
- **AWS Systems Manager:** Supports secure instance management and automated deployment.
- **Amazon CloudWatch:** Collects logs, metrics, and monitoring information.
- **Amazon SNS:** Sends monitoring and security alert notifications.

### Application Traffic Flow

User → CloudFront (HTTPS) → Application Load Balancer → Nginx → Gunicorn → Flask Application → Amazon RDS (MySQL)

The Flask application accesses uploaded files through its S3 integration.

## Security Implementation

The project includes the following security measures:

- Private application and database subnets
- Restricted security group rules
- Private S3 buckets with public access blocked
- Encryption for S3 storage
- IAM roles and least-privilege access policies
- Secure SSH access through a bastion host
- IMDSv2 on the EC2 application instance
- Application authentication and CSRF protection
- Login rate limiting and security headers
- CloudFront HTTPS access
- GitHub Actions authentication using AWS OIDC instead of long-lived AWS access keys

## Backup and Recovery

A scheduled backup script is configured to:

- Create compressed MySQL database backups.
- Upload database backups to a private S3 backup bucket.
- Synchronize application media files to the backup bucket.
- Apply a 30-day lifecycle retention rule to current backup objects.

A database restoration test was performed using a temporary RDS database to verify backup recovery.

## Monitoring and Logging

Amazon CloudWatch is used to collect application, Nginx, authentication, and system monitoring information.

CloudWatch alarms monitor selected application and infrastructure conditions. Amazon SNS is configured to send email notifications when configured alarm thresholds are breached.

## Docker and CI/CD

A Docker image was built and tested successfully. A separate test container returned an HTTP 200 OK response.

GitHub Actions performs Python syntax checks and Docker image builds. The deployment workflow uses GitHub OIDC authentication and AWS Systems Manager to deploy application updates to the EC2 instance.

**Note:** The live production application runs directly on EC2 using Nginx, Gunicorn, Flask, and systemd. The Docker container was tested separately.

## Repository Structure

```text
securedesk-devsecops/
├── .github/
│   └── workflows/
├── docs/
├── infra/
├── scripts/
├── src/
├── requirements.txt
├── Dockerfile
├── .env.example
├── .gitignore
└── README.md
```

## Project Repository

GitHub: https://github.com/dell09-cloud/securedesk-devsecops

## Project Objective

The objective of SecureDesk is to demonstrate how a web application can be deployed and managed using AWS cloud infrastructure and DevSecOps practices, with a focus on security, automation, monitoring, and backup and recovery.

---
                                      
**Developed as a DevSecOps Capstone Project**

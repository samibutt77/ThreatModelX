ThreatModelX

Automated STRIDE/DREAD Threat Modeling Toolkit for Developers

📌 Project Overview

ThreatModelX is an automated security analysis and threat modeling toolkit designed to integrate security early into the Secure Software Development Lifecycle (SSDLC). It automatically generates STRIDE-based threats and DREAD risk scores from design and architecture artifacts, enabling developers to detect and prioritize vulnerabilities before deployment.

The tool reduces dependency on manual security expertise and supports CI/CD-integrated DevSecOps workflows, making security a continuous and automated process.

🎯 Objectives

Automate STRIDE and DREAD threat analysis from design artifacts

Reduce manual effort and security expertise requirements

Provide actionable risk scores and mitigation guidance

Enable security-by-design practices

Integrate with CI/CD pipelines for continuous security assessment

✨ Key Features

📂 Multi-format input support

UML / PlantUML diagrams

Source code

OpenAPI / Swagger specifications

Infrastructure-as-Code (Terraform / CloudFormation)

🔍 Automated system model generation

🛡️ STRIDE-based threat categorization

📊 DREAD risk scoring and prioritization

📄 Comprehensive threat reports (JSON/YAML)

🌐 Interactive web-based interface

🔁 CI/CD pipeline integration (GitHub Actions / Jenkins)

🧱 Secure Design & SSDLC Compliance

ThreatModelX is developed following Secure SDLC (SSDLC) principles and secure coding best practices.

Security Controls Implemented

OWASP Top 10 risks explicitly addressed

Secure authentication with:

Password hashing

MFA (TOTP)

JWT-based authorization

Role-Based Access Control (Admin / Analyst)

Secure file upload handling:

Extension whitelisting

Filename sanitization

CSRF protection and secure session handling

Encryption at rest (AES-256)

HTTPS-only communication

Audit logging for admin actions

Rate-limited APIs

🏗️ Architecture & Technologies
Tech Stack

Backend: Python (Flask)

Frontend: HTML, CSS, JavaScript

Security Frameworks: STRIDE, DREAD

Parsers:

PlantUML / UML

OpenAPI / Swagger

Terraform / CloudFormation (IaC)

Reporting: JSON / YAML

CI/CD: GitHub Actions, Jenkins hooks

📥 Functional Requirements

Upload UML, source code, or IaC files for analysis

Automatic parsing and internal threat model generation

Automated STRIDE threat identification

DREAD risk calculation and prioritization

Secure role-based access (Admin / Analyst)

API support for automation

CI/CD pipeline integration

🧪 Testing & Validation
Security Testing

✅ SQL Injection protection via parameterized queries

✅ XSS prevention using input validation and sanitization

✅ CSRF protection enforced

✅ Secure session handling (no-cache headers)

✅ MFA and RBAC validated

Static Code Analysis (SAST)

Tool Used: Bandit (Python)

Issues fixed:

Hard-coded secrets removed

Insecure temp file usage resolved

Missing input validation fixed

🚀 CI/CD & DevSecOps

ThreatModelX supports integration into CI/CD pipelines, enabling:

Automated threat modeling on design changes

Continuous security assessment

Early vulnerability detection before deployment

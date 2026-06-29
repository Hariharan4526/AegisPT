# PentestLab AI

PentestLab AI is an automated penetration testing platform for authorized security assessments and lab environments.

## Current Scope

Module 1 is implemented: backend foundation plus authentication, projects, targets, scan orchestration, web enumeration, and vulnerability intelligence.

Included in this slice:

- FastAPI application scaffold
- Centralized settings and logging
- SQLAlchemy database layer
- JWT access tokens and refresh tokens
- Password hashing
- Role-based access control primitives
- Audit log model for security events
- Auth API endpoints for register, login, refresh, logout, and me
- Project API endpoints for CRUD and target management
- Scanner API endpoints for Nmap-backed execution and stored results
- Web enumeration API endpoints for ffuf/WhatWeb runs and normalized findings
- Vulnerability API endpoints for CVE enrichment and project-level assessment runs
- API and unit tests
- Docker backend image and Compose stack for PostgreSQL and Redis

## Architecture

The backend follows a clean modular structure:

- `app/core` contains configuration, logging, and security helpers.
- `app/db` contains the SQLAlchemy base and session factory.
- `app/models` contains persistence models.
- `app/schemas` contains Pydantic request and response models.
- `app/repositories` contains database access logic.
- `app/services` contains authentication business logic.
- `app/api` contains dependency injection and route handlers.

This foundation is intentionally small and production-oriented so later modules can plug into the same patterns for projects, targets, scanners, reporting, scheduling, and dashboard data.

## Run Locally

The backend expects Python 3.13.

```bash
cd backend
pip install -e .[dev]
uvicorn app.main:app --reload
```

## Run Tests

```bash
cd backend
pytest
```

## Docker

Build and run the stack with:

```bash
cd docker
docker compose up --build
```

## Next Module

The next module should be report generation and dashboard visualization.

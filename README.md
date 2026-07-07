# Cyber Project

![Web App Screenshot](file:///C:/Users/Anik%20Kumar%20Bhushan/.gemini/antigravity-ide/brain/ec8c6aaa-9f4d-433a-9711-7f79d254f2c5/web_app_screenshot_1783394159860.png)

## Overview

**Cyber Project** is a modern web application built for cybersecurity triage and incident management. It provides a sleek, glassmorphism‑styled dashboard that presents real‑time alerts, threat intelligence, and actionable insights. The backend is powered by Python, leveraging a lightweight MCP server for handling API requests and a Flask‑based web interface.

- **`main.py`** – Core entry point for initializing the application logic.
- **`mcp_server.py`** – Implements the MCP (Modular Component Platform) server for extensible plugin handling.
- **`web/app.py`** – Flask application that serves the UI and API endpoints.
- **`web/templates/index.html`** – Jinja2 template for the responsive front‑end.

The project emphasizes a premium user experience with smooth micro‑animations, dark mode support, and dynamic data visualizations.

## Features

- Real‑time dashboard with threat alerts.
- Modular plugin architecture via MCP.
- Secure authentication and role‑based access.
- Responsive design with modern CSS (glassmorphism, gradients, subtle hover effects).
- Easy extensibility for adding new security data sources.

## Getting Started

```bash
# Clone the repository
git clone https://github.com/yourusername/cyber-project.git
cd cyber-project

# Install dependencies (example using pip)
python -m venv venv
source venv/bin/activate  # on Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run the application
python main.py
```

## CI / CD Workflow

The repository includes a GitHub Actions workflow that runs linting, tests, and builds the Docker image on every push.

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - name: Lint with flake8
        run: flake8 .
      - name: Run tests
        run: pytest
```

![CI Status](https://github.com/yourusername/yourrepo/actions/workflows/ci.yml/badge.svg)

## Contributing

Contributions are welcome! Please fork the repository, create a feature branch, and submit a pull request. Follow the code style guidelines and ensure all tests pass.

## License

This project is licensed under the MIT License – see the `LICENSE` file for details.

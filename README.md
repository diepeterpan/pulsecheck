# PulseCheck

PulseCheck is a small Linux-friendly web application that stores domains in SQLite, discovers open ports for each domain, and monitors the health of those ports on a 10-minute schedule.

## Features

- Import a list of domain names from a text block
- Detect which common ports are listening for each domain
- Maintain the domain list with add, edit, and delete actions
- Schedule automatic health checks every 10 minutes
- View a green/red status page showing online/offline port state and last successful response time

## Run

1. Create a virtual environment and install dependencies:
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
2. Start the app:
   python app.py
3. Open the browser at http://127.0.0.1:8182

## Menu choices

The app also includes a console menu when started directly, allowing you to:

1. Import domains
2. Maintain the domain list
3. View the status report
4. Start the web server
5. Exit

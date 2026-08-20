# Campus Safety Logger

A Flask + SQLite campus safety incident reporting system.

## Features

- Username/password registration
- User login/logout
- User incident reporting
- User report history
- Manager dashboard
- Manager can view all incidents
- Incident search and filters
- Manager can change status and priority
- Manager remarks and update history
- Smart local incident analysis
- Analytics dashboard

## Requirements

Python 3.10+ recommended.

## Setup on Windows

Open PowerShell inside the project folder:

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open:

http://127.0.0.1:5000

## Default manager

Username:
manager

Password:
manager123

Change the manager password in `.env` before using the application seriously.

## Database

The SQLite database is created automatically at:

database/campus_safety.db

Do not manually create tables.

## LLM

The project currently includes a local smart analyzer so the application runs without an external API key.

The function is located at:

services/llm_service.py

You can later connect an actual LLM API inside that function without changing the rest of the application.


## Admin Login

The application now creates the administrator account automatically when the app starts:

- Username: `ADMIN`
- Password: `PASSWORD`

The ADMIN account can see all submitted incident reports and manage their status, priority, and remarks.

## Report Management

Users can:
- Submit a new incident report.
- See the message `your response has been submitted successfully` after submission.
- Edit their own submitted reports.
- Delete their own submitted reports.
- View manager/admin decisions and update history.

## Run

```powershell
cd "C:\campus safety logger\campus-safety-logger"
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

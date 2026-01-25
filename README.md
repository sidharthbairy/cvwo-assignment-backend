# CVWO Assignment: Go + React Forum

## 🚀 Setup Instructions

### Prerequisites
* **Go** (version 1.19 or newer)
* **Node.js** & **Yarn**
* **Git**
* **Docker** (Optional, for containerized run)

### 1. Clone the repository
### 2. Install the dependencies
```bash
go mod tidy
```
### 3. Run the server
```bash
go run cmd/server/main.go
```
### 4. Go to the frontend repository and follow the setup instructions on the README file

### Alternatively, if you prefer to run the entire stack in containers without installing Go/Node locally:
```bash
# Add both frontend and backend directories to a folder, and from the root directory, run
docker compose up --build
```
**Deployed version:** https://cvwo-forum-backend.onrender.com

## 🤖 AI Usage Declaration
### In accordance with the CVWO policy, I utilized AI tools (specifically Gemini 3 Pro) strictly as a research assistant and debugger.
#### 1. I used AI to interpret verbose error logs, specifically for:

CORS Configuration: Debugging cross-origin issues between the Render backend and Netlify frontend.

Docker Build Failures: Resolving "BuildKit" crashes and environment specific errors.

#### 2. I used AI to generate repetitive code structures to save time, including:

SQL Schema: Generating CREATE TABLE statements for the SQLite database.

MUI Layouts: Generating the initial boilerplate for React components (e.g., Material UI Cards and Grids).

#### 3. I used AI to verify my understanding of specific architectural patterns before implementation:

The security trade-offs between storing JWTs in localStorage versus httpOnly cookies.



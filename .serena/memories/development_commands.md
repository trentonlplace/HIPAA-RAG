# Development Commands

## Primary Development Commands (from Makefile)

### Testing Commands
- `make unittest` - Run Python unit tests (excludes azure and functional tests)
- `make unittest-frontend` - Build and test frontend with coverage
- `make functionaltest` - Run functional tests  
- `make python-test` - Run all Python tests (unit + functional, excludes azure)
- `make uitest` - Run UI tests in headless mode using Cypress
- `make ci` - Full CI pipeline: lint + unittest + unittest-frontend + functionaltest

### Code Quality
- `make lint` - Lint Python code using flake8
- `poetry run flake8 code` - Direct flake8 linting
- `poetry run black` - Format Python code (configured in pre-commit)

### Frontend Development
- `make build-frontend` - Build the frontend webapp (npm install + npm run build)
- `cd code/frontend && npm run dev` - Start frontend dev server with hot reload
- `cd code/frontend && npm run test` - Run frontend tests with coverage
- `cd code/frontend && npm run build` - Production build

### Local Development
- `poetry run flask run` - Start Flask API server (from code/ directory)
- `cd code/backend/batch && poetry run func start` - Start Azure Functions locally
- `make docker-compose-up` - Run all services using Docker Compose

### Deployment
- `azd up` - Full deployment (provision + deploy)
- `azd provision` - Provision Azure resources only
- `azd deploy web` - Deploy web app only
- `azd deploy adminweb` - Deploy admin site only  
- `azd deploy function` - Deploy function app only
- `make deploy` - Automated deployment with SPN login

## Poetry Commands (Python Dependency Management)
- `poetry install` - Install all dependencies
- `poetry add <package>` - Add new dependency
- `poetry run <command>` - Run command in poetry environment
- `poetry shell` - Activate poetry shell

## Azure Developer CLI (azd)
- `azd auth login` - Login to Azure
- `azd env set <key> <value>` - Set environment variable
- `azd env list` - List environments
- `azd down` - Destroy Azure resources
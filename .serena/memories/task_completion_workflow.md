# Task Completion Workflow

## Required Commands After Task Completion

### 1. Code Quality Checks (Always Required)
```bash
# Run linting
make lint
# OR directly: poetry run flake8 code

# Format code (if not using pre-commit)
poetry run black code/
```

### 2. Testing (Required for Code Changes)
```bash
# Python unit tests
make unittest

# Frontend tests (if frontend changes)
make unittest-frontend

# Functional tests (for integration changes)
make functionaltest

# Full CI pipeline (comprehensive)
make ci
```

### 3. Build Verification
```bash
# Frontend build check
make build-frontend

# Local development verification
poetry run flask run  # Test API startup
cd code/frontend && npm run dev  # Test frontend startup
```

### 4. Pre-commit Validation
```bash
# Run pre-commit hooks manually
pre-commit run --all-files
```

## Deployment Verification (Production Changes)

### Local Testing
```bash
# Test full stack locally
make docker-compose-up

# Verify Azure Functions
cd code/backend/batch && poetry run func start
```

### Azure Deployment
```bash
# Deploy to development environment
azd deploy web
azd deploy adminweb  
azd deploy function

# Full environment deployment
azd up
```

## Required Checks Before Marking Complete

1. ✅ **Linting passes** - `make lint` returns no errors
2. ✅ **Unit tests pass** - `make unittest` all green
3. ✅ **Frontend tests pass** - `make unittest-frontend` (if applicable)
4. ✅ **Code builds successfully** - No build errors
5. ✅ **Pre-commit hooks pass** - All formatting and checks
6. ✅ **Local development works** - Services start without errors
7. ✅ **Documentation updated** - README/docs reflect changes (if applicable)

## Error Resolution Priority

1. **Syntax/Import Errors** - Fix immediately, blocks everything
2. **Test Failures** - Must be resolved before completion
3. **Linting Errors** - Required for code quality standards
4. **Build Failures** - Prevents deployment
5. **Type Errors** - Important for maintainability (TypeScript)

## Environment-Specific Notes

**Darwin (macOS) Considerations:**
- Azure Functions Core Tools may have ARM64 limitations
- Use Non-DevContainer setup if DevContainer fails
- Ensure Docker Desktop is running for containerized services
- Poetry should be preferred over pip for Python dependencies
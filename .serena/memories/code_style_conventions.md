# Code Style and Conventions

## Python Code Style

### Formatting and Linting
- **Formatter**: Black (version 25.1.0)
- **Linter**: Flake8 (version 7.2.0)
- **Line Length**: 88 characters (Black default)
- **Ignored Rules**: E203, W503, E501 (line length extended to 88)

### Pre-commit Configuration
- Black formatting automatically applied
- Flake8 linting with E501 ignore
- Bicep template generation for infrastructure files

### Python Conventions
- **Version**: Python 3.10+
- **Package Management**: Poetry for dependency management
- **Import Style**: Standard Python import conventions
- **Type Hints**: Encouraged (TypeScript-style where applicable)
- **Docstrings**: Standard Python docstring format
- **Class Naming**: PascalCase (e.g., `DocumentChunking`, `ConfigHelper`)
- **Function Naming**: snake_case (e.g., `get_conversation_response`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `CONFIG_CONTAINER_NAME`)

### Testing Conventions
- **Framework**: pytest with pytest-cov for coverage
- **Test Markers**: 
  - `unittest`: Unit tests (fast)
  - `functional`: Functional tests (require running server)
  - `azure`: Extended tests (slow, run less frequently)
- **Async Testing**: pytest-asyncio for async code testing
- **Mock Framework**: Built-in unittest.mock preferred

## TypeScript/React Code Style

### Frontend Configuration
- **TypeScript**: Strict mode enabled
- **React**: v18.3.1 with hooks pattern
- **Build Tool**: Vite for fast development and building
- **Testing**: Jest with React Testing Library
- **UI Components**: Fluent UI components (@fluentui/react)

### Naming Conventions
- **Components**: PascalCase (e.g., `ChatInterface`)
- **Functions**: camelCase
- **Constants**: UPPER_SNAKE_CASE
- **Files**: kebab-case for components, camelCase for utilities

## Project Structure Patterns

### Backend Structure
```
code/backend/
├── batch/                    # Azure Functions
│   ├── utilities/           # Shared utilities
│   │   ├── helpers/        # Helper classes
│   │   ├── tools/          # Processing tools
│   │   ├── orchestrator/   # LLM orchestration
│   │   └── common/         # Common models
│   └── function_app.py     # Functions entry point
├── api/                     # Flask API endpoints
└── pages/                   # Streamlit admin pages
```

### Configuration Patterns
- Environment variables managed through EnvHelper class
- Configuration objects use dataclass/Pydantic patterns
- Strategy pattern for pluggable components (chunking, loading, orchestration)
- Factory pattern for creating configurable components

### Error Handling
- Structured logging throughout application
- Azure Application Insights integration
- Graceful error handling with user-friendly messages
# Design Patterns and Guidelines

## Architectural Patterns

### Strategy Pattern (Extensively Used)
The codebase heavily uses the Strategy pattern for pluggable components:

**Document Processing Strategies:**
- `DocumentLoadingBase` → Layout, Web, Word, Read implementations
- `DocumentChunkingBase` → FixedSizeOverlap, Layout, Page, Paragraph, JSON
- `OrchestratorBase` → OpenAI Functions, Semantic Kernel, LangChain, Prompt Flow
- `SearchHandlerBase` → Azure Search, PostgreSQL, Integrated Vectorization

**Benefits:** Easy to add new processing strategies without modifying existing code

### Factory Pattern
Used for creating instances based on configuration:
- `EmbedderFactory` - Creates appropriate embedder (Push, PostgreSQL, Integrated Vectorization)
- `DatabaseFactory` - Creates database clients (PostgreSQL/Cosmos DB)
- `get_orchestrator()` - Creates orchestrator based on strategy
- `get_document_loader()` / `get_document_chunker()` - Strategy factories

### Configuration Pattern
Centralized configuration management with layered approach:
- **Environment Layer**: `EnvHelper` for environment variables
- **Configuration Layer**: `ConfigHelper` for complex configurations
- **Settings Classes**: Structured settings objects (ChunkingSettings, LoadingSettings, etc.)

## Code Organization Principles

### Separation of Concerns
- **API Layer** (`api/`) - HTTP endpoints and request handling
- **Business Logic** (`batch/utilities/`) - Core processing logic
- **UI Layer** (`pages/`, `frontend/`) - User interfaces
- **Infrastructure** (`infra/`) - Deployment and infrastructure

### Single Responsibility Principle
Each class has a focused responsibility:
- `LLMHelper` - Only handles LLM interactions
- `AzureSearchHelper` - Only handles search operations
- `AzureBlobStorageClient` - Only handles blob storage
- `ConversationLogger` - Only handles conversation logging

### Dependency Injection
Configuration and dependencies injected rather than hardcoded:
- Environment variables through `EnvHelper`
- Configuration objects passed to constructors
- Strategy instances created by factories

## Error Handling Patterns

### Structured Logging
Consistent logging throughout with structured messages:
```python
logger = logging.getLogger(__name__)
logger.error(f"Failed to process document: {filename}", exc_info=True)
```

### Graceful Degradation
- Fallback mechanisms for optional features
- Content safety checks as optional layer
- Multiple orchestration strategies as fallbacks

### Exception Handling
- Specific exception types for different failure modes
- Proper exception chaining and context preservation
- User-friendly error messages in UI layers

## Data Flow Patterns

### Pipeline Pattern
Document processing follows a clear pipeline:
1. **Upload** → Blob Storage
2. **Queue** → Processing Queue
3. **Extract** → Document Intelligence
4. **Chunk** → Chunking Strategy
5. **Embed** → Embedding Model
6. **Index** → Search Index + Database

### Event-Driven Processing
- Azure Functions triggered by blob events
- Queue-based processing for scalability
- Asynchronous processing patterns

## Security Patterns

### Authentication Strategies
- **API Keys**: Traditional key-based authentication
- **RBAC**: Role-based access control with Azure AD
- **Key Vault Integration**: Secure secret management

### Data Protection
- Content safety filtering before processing
- Secure blob storage with appropriate access controls
- Conversation data isolated by user/tenant

## Testing Patterns

### Test Organization
- **Unit Tests**: Fast, isolated tests (`unittest` marker)
- **Functional Tests**: Integration tests with mocked services (`functional` marker) 
- **Azure Tests**: Full integration tests (`azure` marker)

### Mocking Strategy
- Mock external Azure services for unit tests
- Use pytest fixtures for common test setup
- Separate test configuration from production

## Performance Patterns

### Caching
- Configuration caching to avoid repeated loads
- Search result caching where appropriate
- Embedding caching for repeated content

### Asynchronous Processing
- Azure Functions for scalable processing
- Queue-based workload distribution
- Non-blocking UI operations

### Resource Management
- Connection pooling for database connections
- Proper resource cleanup in finally blocks
- Streaming for large document processing

## Frontend Patterns

### Component Architecture
- Functional components with React hooks
- Fluent UI components for consistency
- TypeScript for type safety

### State Management
- Local state with useState for component state
- Context API for shared application state
- Proper cleanup of subscriptions and timers
# Codebase Structure

## High-Level Architecture

```
HIPAA-RAG/
├── code/                    # Main application code
│   ├── backend/            # Python backend services
│   ├── frontend/           # TypeScript React frontend
│   ├── app.py             # Main Flask application entry
│   └── create_app.py      # Flask app factory
├── infra/                 # Infrastructure as Code (Bicep)
├── docker/                # Docker configuration
├── tests/                 # Integration and E2E tests
├── docs/                  # Documentation
├── data/                  # Sample data for testing
├── scripts/               # Utility scripts
└── extensions/            # Teams and other extensions
```

## Backend Structure (`code/backend/`)

### Core Components
- **`batch/`** - Azure Functions for document processing
  - `function_app.py` - Functions entry point
  - `utilities/` - Shared business logic
    - `helpers/` - Core helper classes (Config, LLM, Search, etc.)
    - `orchestrator/` - LLM orchestration strategies (OpenAI, LangChain, Semantic Kernel)
    - `document_loading/` - Document loading strategies
    - `document_chunking/` - Text chunking strategies  
    - `search/` - Search handler implementations
    - `chat_history/` - Database clients for conversation storage
    - `tools/` - Processing tools and plugins

- **`api/`** - Flask REST API endpoints
  - `chat_history.py` - Conversation management endpoints

- **`pages/`** - Streamlit admin interface pages
  - `01_Ingest_Data.py` - Document upload interface
  - `02_Explore_Data.py` - Data exploration tools
  - `03_Delete_Data.py` - Data management
  - `04_Configuration.py` - System configuration

## Frontend Structure (`code/frontend/`)

```
frontend/
├── src/                   # TypeScript React source
├── public/               # Static assets
├── package.json          # Node.js dependencies
├── tsconfig.json         # TypeScript configuration
├── vite.config.ts        # Vite build configuration
└── jest.config.ts        # Jest test configuration
```

## Key Design Patterns

### Strategy Pattern
- **Document Loading**: Multiple strategies (Layout, Web, Word, Read)
- **Document Chunking**: Fixed size, Layout, Page, Paragraph, JSON
- **Orchestration**: OpenAI Functions, Semantic Kernel, LangChain, Prompt Flow
- **Search Handlers**: Azure Search, PostgreSQL, Integrated Vectorization

### Factory Pattern
- `EmbedderFactory` - Creates appropriate embedder based on configuration
- `DatabaseFactory` - Creates database clients (PostgreSQL/Cosmos DB)
- Strategy factories for document processing components

### Configuration Management
- `ConfigHelper` - Centralized configuration management
- `EnvHelper` - Environment variable handling with defaults
- `SecretHelper` - Azure Key Vault integration for secrets

## Database Architecture

### Dual Database Support
- **PostgreSQL** - Relational database with pgvector for embeddings
- **Cosmos DB** - NoSQL document database for chat history
- **Azure AI Search** - Vector search and document indexing

### Data Flow
1. Documents uploaded to Azure Blob Storage
2. Azure Functions process documents (extract, chunk, embed)
3. Processed data stored in search index + database
4. Chat queries retrieve relevant chunks and generate responses
5. Conversation history stored in selected database

## External Dependencies

### Azure Services
- Azure OpenAI (GPT models + embeddings)
- Azure AI Search (vector search)  
- Azure Blob Storage (document storage)
- Azure Functions (serverless processing)
- Azure App Service (web hosting)
- Azure Key Vault (secrets management)
- Azure Application Insights (monitoring)

### Processing Pipeline
1. **Ingestion** → Blob Storage
2. **Processing** → Azure Functions (extract, chunk, embed)
3. **Indexing** → Azure AI Search + Database
4. **Querying** → Retrieval + LLM generation
5. **Response** → Chat interface with source citations
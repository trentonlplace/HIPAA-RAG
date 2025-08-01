# HIPAA-RAG Project Overview

## Project Purpose
This is the "Chat with your data" Solution Accelerator - a comprehensive RAG (Retrieval Augmented Generation) system that enables natural language chat interfaces over private data using Azure AI services.

**Key Features:**
- Chat with Azure OpenAI models using private data
- Document upload and processing (multiple file types)
- Web page indexing capability  
- Advanced prompt configuration
- Multiple chunking strategies
- Support for PostgreSQL and Cosmos DB backends
- Admin interface for data management
- Teams extension support
- Speech-to-text functionality

## Technology Stack

### Backend (Python)
- **Framework**: Flask with async support
- **AI/ML**: Azure OpenAI, LangChain, Semantic Kernel
- **Search**: Azure AI Search, pgvector (PostgreSQL)
- **Storage**: Azure Blob Storage, Azure Cosmos DB, PostgreSQL
- **Processing**: Azure Functions, Azure Document Intelligence
- **Authentication**: Azure Identity (RBAC or API keys)
- **Admin Interface**: Streamlit

### Frontend (TypeScript/React)
- **Framework**: React 18.3.1 with TypeScript
- **Build Tool**: Vite
- **UI Library**: Fluent UI (@fluentui/react)
- **Routing**: React Router DOM
- **Styling**: PostCSS
- **Testing**: Jest with React Testing Library

### Infrastructure
- **Orchestration**: Azure Developer CLI (azd)
- **IaC**: Bicep templates
- **Containerization**: Docker with Docker Compose
- **CI/CD**: GitHub Actions
- **Monitoring**: Azure Application Insights

## Architecture
The system follows a microservices architecture with:
1. **Web Frontend**: React TypeScript app for chat interface
2. **Admin Interface**: Streamlit app for data management
3. **API Backend**: Flask app for chat API endpoints
4. **Batch Processing**: Azure Functions for document processing
5. **Data Layer**: Azure AI Search + PostgreSQL/Cosmos DB
6. **Storage**: Azure Blob Storage for documents

## Target Use Cases
- Employee onboarding assistance
- Financial advisor preparation
- Contract review and summarization
- Internal knowledge base querying
- Document-based Q&A systems
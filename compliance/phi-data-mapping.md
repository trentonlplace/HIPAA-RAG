# PHI Data Mapping and Classification

## Overview
This document identifies all components, data flows, and storage locations within the HIPAA-RAG system that handle, process, store, or transmit Protected Health Information (PHI) as defined by HIPAA.

## PHI Definition and Identification

### What Constitutes PHI in This System
Protected Health Information includes any individually identifiable health information that is:
- Created, received, maintained, or transmitted by the system
- Related to past, present, or future physical or mental health
- Related to payment for healthcare services
- Could reasonably identify an individual

### Common PHI Data Types in Healthcare Documents
- Patient names, addresses, phone numbers, email addresses
- Medical record numbers, account numbers, SSNs
- Birth dates, admission/discharge dates
- Diagnoses, treatment plans, medication lists
- Lab results, imaging reports, clinical notes
- Insurance information and billing records
- Biometric identifiers (fingerprints, voice prints)
- Photographs and medical images

## PHI Data Flow Mapping

### 1. Document Ingestion (HIGH RISK)

#### Component: Admin Interface (`code/backend/pages/01_Ingest_Data.py`)
- **PHI Exposure**: HIGH
- **Data Types**: Raw healthcare documents containing full PHI
- **Risk Level**: CRITICAL
- **Current Protection**: None
- **Required Controls**:
  - Multi-factor authentication
  - Role-based access control
  - Audit logging of all uploads
  - Virus scanning and content validation
  - Temporary file encryption

#### Component: Azure Blob Storage
- **PHI Exposure**: HIGH
- **Data Types**: Original documents with full PHI
- **Risk Level**: CRITICAL
- **Current Protection**: Azure Storage Service Encryption
- **Required Controls**:
  - Customer-managed encryption keys
  - Private endpoints
  - Access logging and monitoring
  - Data retention policies
  - Secure deletion procedures

#### Component: Processing Queue (`DOCUMENT_PROCESSING_QUEUE_NAME`)
- **PHI Exposure**: MEDIUM
- **Data Types**: Document metadata and file references
- **Risk Level**: HIGH
- **Current Protection**: None
- **Required Controls**:
  - Message encryption
  - Access controls
  - Queue monitoring
  - Message retention limits

### 2. Document Processing Pipeline (HIGH RISK)

#### Component: Azure Functions (`code/backend/batch/`)
- **PHI Exposure**: HIGH
- **Data Types**: Full document content during processing
- **Risk Level**: CRITICAL
- **Current Protection**: None
- **Required Controls**:
  - Function-level authentication
  - Environment variable encryption
  - Temporary storage encryption
  - Memory protection
  - Processing audit logs

#### Subcomponent: `batch_start_processing.py`
- **PHI Access**: Reads raw documents from blob storage
- **Processing**: Document parsing and initial analysis
- **Risk**: Full PHI exposure during processing

#### Subcomponent: Document Intelligence Service
- **PHI Access**: Processes document content for text extraction
- **Processing**: OCR and layout analysis
- **Risk**: PHI sent to Azure Cognitive Services
- **Required**: Business Associate Agreement with Microsoft

#### Subcomponent: Chunking Strategies (`utilities/document_chunking/`)
- **PHI Access**: Splits documents containing PHI
- **Processing**: Text segmentation and overlap management
- **Risk**: PHI distributed across multiple chunks
- **Required**: PHI-aware chunking that maintains context

#### Subcomponent: Embedding Generation
- **PHI Access**: Converts PHI text to vector embeddings
- **Processing**: Sends PHI to Azure OpenAI for embedding
- **Risk**: HIGH - PHI sent to external AI service
- **Required**: 
  - Business Associate Agreement with Microsoft
  - Audit all embedding requests
  - Consider local embedding models for sensitive data

### 3. Data Storage Layer (CRITICAL RISK)

#### Component: Azure AI Search Index
- **PHI Exposure**: HIGH
- **Data Types**: 
  - Document chunks containing PHI
  - Vector embeddings derived from PHI
  - Document metadata with potential identifiers
- **Risk Level**: CRITICAL
- **Current Protection**: Azure Search encryption at rest
- **Required Controls**:
  - Customer-managed encryption keys
  - Field-level encryption for sensitive fields
  - Access control lists
  - Search query auditing
  - Data retention policies

#### Component: PostgreSQL Database (`pgvector`)
- **PHI Exposure**: HIGH
- **Data Types**:
  - Conversation history with PHI queries
  - User session data
  - Document metadata
  - Vector embeddings
- **Risk Level**: CRITICAL
- **Current Protection**: Basic PostgreSQL security
- **Required Controls**:
  - Transparent Data Encryption (TDE)
  - Column-level encryption for PHI fields
  - Database access controls
  - Connection encryption (SSL/TLS)
  - Audit logging of all queries
  - Regular security updates

#### Component: Cosmos DB (Alternative)
- **PHI Exposure**: HIGH
- **Data Types**: Same as PostgreSQL
- **Risk Level**: CRITICAL
- **Required Controls**: Same as PostgreSQL plus Cosmos-specific controls

### 4. Query Processing (HIGH RISK)

#### Component: Chat API (`code/backend/api/chat_history.py`)
- **PHI Exposure**: HIGH
- **Data Types**: User queries containing PHI, system responses
- **Risk Level**: CRITICAL
- **Current Protection**: None
- **Required Controls**:
  - API authentication and authorization
  - Input validation and sanitization
  - Rate limiting
  - Request/response logging
  - Session management

#### Component: Search Handlers (`utilities/search/`)
- **PHI Access**: Queries search index for PHI-containing documents
- **Processing**: Retrieval and ranking of PHI data
- **Risk**: PHI exposure in search results
- **Required**: Query auditing and access controls

#### Component: LLM Orchestration (`utilities/orchestrator/`)
- **PHI Access**: Sends PHI context to language models
- **Processing**: Combines PHI data with user queries
- **Risk**: CRITICAL - PHI sent to Azure OpenAI
- **Required**:
  - Business Associate Agreement
  - Prompt filtering for PHI
  - Response auditing
  - Context limitation controls

### 5. Frontend and User Interface (MEDIUM RISK)

#### Component: React Frontend
- **PHI Exposure**: MEDIUM
- **Data Types**: Chat responses containing PHI, document citations
- **Risk Level**: HIGH
- **Current Protection**: HTTPS
- **Required Controls**:
  - Client-side encryption
  - Session timeout
  - Screen recording protection
  - Copy/paste restrictions for PHI
  - Secure storage (no localStorage for PHI)

#### Component: Admin Interface (`code/backend/pages/`)
- **PHI Exposure**: HIGH
- **Data Types**: Document content, system configuration, user data
- **Risk Level**: CRITICAL
- **Required Controls**:
  - Administrative access controls
  - Activity monitoring
  - Data masking in UI
  - Secure configuration management

## PHI Data Classification Matrix

| Component | PHI Type | Risk Level | Encryption Required | Access Controls | Audit Required |
|-----------|----------|------------|-------------------|-----------------|----------------|
| Blob Storage | Raw Documents | CRITICAL | Customer-managed keys | RBAC + Private endpoints | All access |
| Search Index | Document chunks | CRITICAL | Field-level | Query-based | All searches |
| Database | Conversations | CRITICAL | Column-level | Row-level security | All queries |
| Processing Queue | Metadata | HIGH | Message encryption | Function-level | All messages |
| Azure Functions | Temporary data | HIGH | Memory encryption | Function identity | All executions |
| API Endpoints | Request/Response | HIGH | TLS 1.3 | Authentication | All requests |
| Frontend | Display data | MEDIUM | Client-side | Session-based | User actions |

## Data Retention and Lifecycle

### PHI Data Lifecycle Requirements

1. **Creation/Ingestion**
   - Immediate encryption upon upload
   - PHI classification tagging
   - Audit log creation

2. **Processing**
   - Encrypted processing pipelines
   - Minimal retention in temporary storage
   - Secure cleanup after processing

3. **Storage**
   - Long-term encrypted storage
   - Regular access reviews
   - Automated retention enforcement

4. **Access**
   - Logged and monitored access
   - Purpose limitation enforcement
   - User authorization validation

5. **Destruction**
   - Secure deletion procedures
   - Certificate of destruction
   - Audit trail of deletion

### Retention Schedules

- **Original Documents**: 7 years (HIPAA requirement)
- **Processed Chunks**: 7 years
- **Conversation History**: 7 years
- **Audit Logs**: 7 years
- **System Logs**: 3 years
- **Temporary Files**: Immediate deletion after processing

## PHI Handling Procedures

### Required PHI Safeguards

1. **Minimum Necessary Standard**
   - Only access PHI required for specific function
   - Implement role-based access controls
   - Regular access reviews and updates

2. **Purpose Limitation**
   - Use PHI only for authorized purposes
   - No secondary use without authorization
   - Clear data use policies

3. **User Authentication**
   - Multi-factor authentication required
   - Regular password updates
   - Account lockout procedures

4. **Data Integrity**
   - Hash verification for documents
   - Change tracking and versioning
   - Corruption detection and recovery

## De-identification Requirements

### Safe Harbor Method Implementation
For analytics and reporting, implement automated de-identification:

1. **Direct Identifiers** (Remove completely):
   - Names, addresses, phone numbers
   - Social Security numbers
   - Medical record numbers
   - Account numbers, dates of birth

2. **Quasi-identifiers** (Generalize):
   - Geographic subdivisions (zip codes)
   - Dates (year only, age ranges)
   - Other identifying numbers

3. **Free Text Scrubbing**:
   - Named entity recognition for PHI
   - Automatic redaction/masking
   - Manual review processes

## Business Associate Requirements

### Required BAAs for Azure Services
- Azure OpenAI Service
- Azure Document Intelligence
- Azure AI Search
- Azure Storage
- Azure Monitor/Application Insights

### BAA Compliance Monitoring
- Regular BAA compliance audits
- Service configuration reviews
- Data processing agreement updates
- Incident notification procedures

## Compliance Testing and Validation

### PHI Handling Tests
1. **Data Discovery Tests**: Verify all PHI locations identified
2. **Access Control Tests**: Validate RBAC implementation
3. **Encryption Tests**: Confirm end-to-end encryption
4. **Audit Log Tests**: Verify comprehensive logging
5. **Data Retention Tests**: Confirm retention policy enforcement
6. **Incident Response Tests**: Test PHI breach procedures

### Continuous Monitoring
- Automated PHI detection and classification
- Real-time access monitoring
- Data loss prevention (DLP) systems
- Regular vulnerability assessments
- Compliance dashboard and reporting
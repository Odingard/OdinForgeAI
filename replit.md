# OdinForge AI Platform

## Overview

OdinForge AI (Adversarial Exposure Validation) is a next-generation AI-powered security platform that performs autonomous exploit validation and attack simulation. The platform analyzes security exposures (CVEs, misconfigurations, behavioral anomalies, network vulnerabilities) and uses AI to determine exploitability, construct attack paths using MITRE ATT&CK techniques, assess business impact, and generate remediation recommendations.

The application follows a full-stack TypeScript architecture with a React frontend, Express backend, PostgreSQL database, and real-time WebSocket communication for live evaluation progress updates.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript
- **Routing**: Wouter (lightweight React router)
- **State Management**: TanStack React Query for server state, local React state for UI
- **Styling**: Tailwind CSS with shadcn/ui component library (New York style)
- **Theme**: Dark/light mode support with cyber-security aesthetics
- **Real-time Updates**: WebSocket connection for live evaluation progress

The frontend is organized around a dashboard-centric design with:
- Main dashboard showing evaluation statistics and active assessments
- **Guided Evaluation Wizard** for non-technical users with 8 infrastructure categories (Web Servers, Databases, Cloud Storage, Containers, Network, Identity, Email, Applications)
- Evaluation table with filtering and sorting capabilities
- Detail views for individual evaluation results including attack path visualization
- Modal-based workflows for creating new evaluations and viewing progress
- Risk Dashboard with interactive visualizations (attack graphs, heatmaps, gauges)
- Reports page for generating executive, technical, and compliance reports
- Batch Jobs page for parallel security assessments

### Evaluation Wizard System
The platform includes a guided wizard (`client/src/components/EvaluationWizard.tsx`) for non-technical administrators:
- **Templates** (`client/src/lib/evaluation-templates.ts`): 8 infrastructure categories with specific types, versions, and configuration questions
- **Smart Priority Calculation**: Layered risk scoring considers internet exposure, data sensitivity, patch status, authentication methods, and risk factor combinations
- **Auto-generated Descriptions**: Converts wizard answers into structured technical descriptions for AI analysis
- **Dual Paths**: Dashboard offers both "Guided Wizard" (template-based) and "Quick Evaluation" (manual entry) options

### Backend Architecture
- **Framework**: Express.js with TypeScript
- **Build Tool**: Vite for frontend, esbuild for server bundling
- **API Design**: RESTful endpoints under `/api/` prefix
- **Real-time**: WebSocket server on `/ws` path for progress events

Key backend services:
- **AEV Service** (`server/services/aev.ts`): Core AI analysis using OpenAI API to evaluate security exposures
- **WebSocket Service** (`server/services/websocket.ts`): Broadcasts evaluation progress and completion events
- **Storage Layer** (`server/storage.ts`): Database abstraction using Drizzle ORM
- **Report Generator** (`server/services/report-generator.ts`): Generates executive, technical, and compliance reports
- **Agent Orchestrator** (`server/services/agents/orchestrator.ts`): Coordinates AI agent workflow for evaluations

### Data Storage
- **Database**: PostgreSQL with Drizzle ORM
- **Schema Location**: `shared/schema.ts` (shared between frontend and backend)
- **Key Tables**:
  - `users`: Basic user authentication
  - `aev_evaluations`: Stores evaluation requests with asset info, exposure type, priority
  - `aev_results`: Stores AI analysis results including exploitability scores, attack paths, recommendations
  - `reports`: Stores generated reports (executive, technical, compliance)
  - `batch_jobs`: Tracks batch evaluation jobs with progress and results
  - `scheduled_scans`: Stores scheduled scan configurations
  - `evaluation_history`: Tracks historical evaluation snapshots for drift detection
  - `endpoint_agents`: Tracks deployed endpoint agents with hashed API keys and metadata
  - `agent_telemetry`: Stores system info, metrics, and security findings from agents
  - `agent_findings`: Individual security findings detected by agents with auto-evaluation triggers

### Endpoint Agent System
The platform includes a live agent deployment system for real-time security monitoring:
- **Agent Registration**: Agents register via `/api/agents/register` and receive a one-time API key (bcrypt hashed for storage)
- **Telemetry Ingestion**: Agents send system data and security findings via `/api/agents/telemetry`
- **Auto-evaluation Triggers**: Critical/high severity findings automatically create AEV evaluations
- **Deduplication**: Findings are deduplicated using composite keys (findingType|title|affectedComponent)
- **Sample Agent**: Python agent script at `scripts/odinforge_agent.py` with HTTPS enforcement, exponential backoff, and secure credential handling

**Security Features**:
- API keys hashed with bcrypt before storage (plaintext only shown once at registration)
- Zod validation on all agent API endpoints
- HTTPS enforcement in Python agent (blocks non-localhost HTTP connections)

### AI Integration
- **Provider**: OpenAI API (configurable via environment variables)
- **Purpose**: Analyzes security exposures to determine exploitability, construct attack paths, assess impact, and generate remediation steps
- **Configuration**: `AI_INTEGRATIONS_OPENAI_API_KEY` and `AI_INTEGRATIONS_OPENAI_BASE_URL` environment variables

### Design System
The platform follows custom design guidelines (`design_guidelines.md`) combining Material Design component structure with cyber-security aesthetics:
- Typography: Inter for UI, JetBrains Mono for technical data
- Color scheme: Dark-first with cyan/blue accent gradients for security branding
- Data-dense layouts optimized for security professionals

## External Dependencies

### Database
- **PostgreSQL**: Primary data store (requires `DATABASE_URL` environment variable)
- **Drizzle ORM**: Type-safe database queries and migrations
- **connect-pg-simple**: PostgreSQL session store

### AI Services
- **OpenAI API**: Powers the AEV analysis engine for exploit validation
  - Requires `AI_INTEGRATIONS_OPENAI_API_KEY`
  - Optional `AI_INTEGRATIONS_OPENAI_BASE_URL` for custom endpoints

### Frontend Libraries
- **shadcn/ui**: Pre-built accessible React components (Radix UI primitives)
- **TanStack React Query**: Data fetching and caching
- **Lucide React**: Icon library
- **date-fns**: Date formatting utilities

### Development Tools
- **Vite**: Frontend development server and build tool
- **tsx**: TypeScript execution for development
- **Drizzle Kit**: Database migration tooling

### Real-time Communication
- **ws**: WebSocket library for server-side real-time communication
- Native WebSocket API on client for receiving evaluation progress updates
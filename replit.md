# NEXUS AEV Platform

## Overview

NEXUS AEV (Adversarial Exposure Validation) is a next-generation AI-powered security platform that performs autonomous exploit validation and attack simulation. The platform analyzes security exposures (CVEs, misconfigurations, behavioral anomalies, network vulnerabilities) and uses AI to determine exploitability, construct attack paths using MITRE ATT&CK techniques, assess business impact, and generate remediation recommendations.

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
- Evaluation table with filtering and sorting capabilities
- Detail views for individual evaluation results including attack path visualization
- Modal-based workflows for creating new evaluations and viewing progress

### Backend Architecture
- **Framework**: Express.js with TypeScript
- **Build Tool**: Vite for frontend, esbuild for server bundling
- **API Design**: RESTful endpoints under `/api/` prefix
- **Real-time**: WebSocket server on `/ws` path for progress events

Key backend services:
- **AEV Service** (`server/services/aev.ts`): Core AI analysis using OpenAI API to evaluate security exposures
- **WebSocket Service** (`server/services/websocket.ts`): Broadcasts evaluation progress and completion events
- **Storage Layer** (`server/storage.ts`): Database abstraction using Drizzle ORM

### Data Storage
- **Database**: PostgreSQL with Drizzle ORM
- **Schema Location**: `shared/schema.ts` (shared between frontend and backend)
- **Key Tables**:
  - `users`: Basic user authentication
  - `aev_evaluations`: Stores evaluation requests with asset info, exposure type, priority
  - `aev_results`: Stores AI analysis results including exploitability scores, attack paths, recommendations

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
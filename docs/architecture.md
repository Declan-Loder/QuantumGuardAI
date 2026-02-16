# System Architecture

QuantumGuard AI is a **privacy-first, agentic cybersecurity framework** built around multi-agent collaboration, graph-based threat intelligence, federated learning, and quantum-resistant cryptography.

The design follows zero-trust principles, minimizes data movement, enables self-improvement without central data aggregation, and prepares for post-quantum threats — all while remaining modular and extensible for enterprise integration.

## High-Level Overview

```mermaid
graph TD
    A[External Data Sources<br>PCAPs • Logs • NetFlow • EDR] -->|Ingest| B[Tools Layer]
    B --> C[Agents Layer]
    C --> D[Models Layer]
    D --> E[Privacy & Crypto Layer]
    E --> F[Orchestration & Self-Optimization]
    F -->|Actions| G[Response & Alerting]
    G -->|Feedback| C
    subgraph "Federated Learning Plane"
        H[Client Node 1] -.->|Model Updates<br>(no raw data)| I[Flower Server]
        J[Client Node 2] -.-> I
        K[Client Node N] -.-> I
        I -->|Aggregated Model| H & J & K
    end
    subgraph "Quantum-Resistant Plane"
        L[Post-Quantum Crypto<br>ML-KEM • ML-DSA • SLH-DSA]
        E --> L
    end
    style A fill:#f9f,stroke:#333
    style G fill:#bbf,stroke:#333
    style Federated Learning Plane fill:#dfd,stroke:#333,stroke-dasharray: 5 5
    style Quantum-Resistant Plane fill:#fdd,stroke:#333,stroke-dasharray: 5 5

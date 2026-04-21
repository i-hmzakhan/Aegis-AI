Aegis-AI: Technical Documentation & Forensic Pipeline
Aegis-AI is a high-fidelity malware analysis system designed to perform automated feature extraction and heuristic triage on Windows Portable Executable (PE) binaries.

🏗 System Architecture & Pipeline
The project implements a multi-stage pipeline that bridges a PHP-based management layer with a Python-based inference engine:

Binary Ingestion: Secure transfer of PE files to a localized quarantine zone.

Feature Extraction: Utilization of pefile and math libraries to extract raw telemetry from headers, sections, and import tables.

Heuristic Analysis: A LightGBM (Gradient Boosting Machine) classifier processes a 33-dimensional feature vector.

Forensic Ingestion: Relational mapping of AI predictions and raw feature DNA into a MariaDB warehouse.

Intelligence Hierarchy: A custom-built SQL "Upsert" logic that prioritizes Human Manual Verdicts over machine-generated probabilities.

🧠 Intelligence Engine (V3)
The core of Aegis-AI is the V3 Heuristic Engine, which focuses on high-entropy features that are difficult for malware authors to obfuscate.

Primary Feature Dimensions (33 Total)
Structural Entropy: Calculated across the entire binary to identify packed or encrypted payloads.

Header Telemetry: Analysis of COFF characteristics, Optional Header magic numbers, and subsystem versions.

Section Analysis: Comparative study of virtual vs. raw sizes and section counts to detect hollowed or injected code.

Resource & Import Metadata: Tracking of DLL characteristics, has_debug flags, and TLS callbacks.

💾 Database Schema & Forensic Integrity
The database is designed to handle "Big Data" forensic artifacts while maintaining strict referential integrity.

SHA-256 Fingerprinting: Every binary is hashed prior to processing. This hash serves as the Primary Key for deduplication, ensuring that the Intelligence Warehouse only stores unique "File DNA."

JSON-Blob Storage: To maintain the 33-dimensional feature space without schema bloating, features are stored as a structured JSON object in the malware_features table.

Referential Cascade: A 1:1 relationship between malware_reports and malware_features ensures that deleting a forensic report automatically purges its associated DNA artifacts.

🛡 Security Implementations
Quarantine Isolation: Files are analyzed in a non-executable state within a restricted directory and unlinked (deleted) immediately post-analysis to prevent accidental execution on the host.

Zero-Persistence Sessions: PHP session cookies are restricted to lifetime = 0 and sessionStorage parity, ensuring that forensic data is not accessible after the browser process terminates.

🛠 Deployment Configuration
Inference Environment: Python 3.11+ running in an isolated .venv.

Web Tier: Apache/PHP 8.2 configured via XAMPP.

Data Tier: MariaDB (Port 3307) with a dedicated service account inventory_app.

Technical Lead: Hamza Khan (BSAI, UEAS Swat)

Project Scope: Database Management Systems & AI Integration

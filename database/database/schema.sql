-- 1. Create the Project Warehouse
CREATE DATABASE IF NOT EXISTS smart_inventory;
USE smart_inventory;

-- 2. Create the Inventory Scans Table
CREATE TABLE inventory_scans (
    -- Universal Traits (The Relational Anchor)
    scan_id INT AUTO_INCREMENT PRIMARY KEY,
    scanner_location VARCHAR(100) DEFAULT 'Main_Warehouse',
    total_count INT NOT NULL,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Unique Specifications (The AI Feature Store)
    -- This stores the full JSON output we saw yesterday
    ai_payload JSON NOT NULL,
    
    -- Performance Optimization: Virtual Indexing
    -- This automatically extracts the confidence of the first item detected
    top_confidence FLOAT GENERATED ALWAYS AS (
        JSON_UNQUOTE(JSON_EXTRACT(ai_payload, '$.items[0].confidence'))
    ) VIRTUAL
) ENGINE=InnoDB; -- Optimized for transactions and row-level locking
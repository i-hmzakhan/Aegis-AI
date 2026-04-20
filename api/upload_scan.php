<?php
require_once 'db_config.php';

// Only allow POST requests (Security Perimeter)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the raw JSON data from the AI script
    $json_data = file_get_contents('php://input');
    $decoded_data = json_decode($json_data, true);

    if ($decoded_data) {
        $total_count = $decoded_data['total_items'];
        
        // Prepare the SQL (Prevents SQL Injection)
        $sql = "INSERT INTO inventory_scans (total_count, ai_payload) VALUES (?, ?)";
        $stmt = $pdo->prepare($sql);
        
        try {
            $stmt->execute([$total_count, $json_data]);
            echo json_encode(["status" => "success", "message" => "Scan saved to Warehouse"]);
        } catch (Exception $e) {
            echo json_encode(["status" => "error", "message" => $e->getMessage()]);
        }
    }
}
?>
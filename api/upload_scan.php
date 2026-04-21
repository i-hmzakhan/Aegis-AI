<?php
require_once 'db_config.php'; // Ensure this points to your NEW database

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode($_POST['json_data'], true);
    $hash = $data['hash'];

    // 1. DEDUPLICATION: Check if this file has been seen
    $check = $pdo->prepare("SELECT report_id FROM malware_reports WHERE sha256_hash = ?");
    $check->execute([$hash]);
    
    if ($check->rowCount() > 0) {
        die(json_encode(["status" => "exists", "message" => "Analysis already archived."]));
    }

    // 2. CLASSIFICATION
    $prob = $data['probability'];
    $level = ($prob > 0.5) ? 'CRITICAL' : (($prob > 0.15) ? 'SUSPICIOUS' : 'CLEAN');

    // 3. TRANSACTIONAL INSERT
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("INSERT INTO malware_reports (file_name, sha256_hash, entropy_score, malware_probability, threat_level) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$data['file_name'], $hash, $data['entropy'], $prob, $level]);
        
        $report_id = $pdo->lastInsertId();
        $f = $data['features'];
        
        $stmt2 = $pdo->prepare("INSERT INTO malware_features (report_id, num_strings, import_count, section_count, has_debug, size_of_code, full_feature_json) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt2->execute([
            $report_id, 
            $f['num_strings'], 
            $f['imports'], 
            $f['sections'], 
            $f['debug'], 
            $f['code_size'], 
            json_encode($f['full_set'])
        ]);
        
        $pdo->commit();
        echo json_encode(["status" => "success", "report_id" => $report_id, "threat" => $level]);
    } catch (Exception $e) {
        $pdo->rollBack();
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
}
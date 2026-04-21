<?php
require_once 'db_config.php';

// 1. Executive Summary Metrics
$total_scans = $pdo->query("SELECT COUNT(*) FROM malware_reports")->fetchColumn();
$critical_threats = $pdo->query("SELECT COUNT(*) FROM malware_reports WHERE threat_level = 'CRITICAL'")->fetchColumn();
$avg_entropy = $pdo->query("SELECT AVG(entropy_score) FROM malware_reports")->fetchColumn();

// 2. Fetch the Forensic Reports
$stmt = $pdo->query("SELECT r.*, f.num_strings, f.import_count, f.section_count 
                     FROM malware_reports r 
                     JOIN malware_features f ON r.report_id = f.report_id 
                     ORDER BY r.captured_at DESC LIMIT 10");
$reports = $stmt->fetchAll();
?>

<div class="container">
    <h1>🛡️ Malware Forensic Warehouse</h1>
    
    <div class="analytics-row" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px;">
        <div class="stat-box" style="border-bottom: 3px solid #ff3366;">
            <div class="label">Total Samples</div>
            <div class="value"><?php echo $total_scans; ?></div>
        </div>
        <div class="stat-box" style="border-bottom: 3px solid #ffcc00;">
            <div class="label">Avg Entropy</div>
            <div class="value"><?php echo round($avg_entropy, 2); ?></div>
        </div>
        <div class="stat-box" style="border-bottom: 3px solid #00ffcc;">
            <div class="label">Critical Threats</div>
            <div class="value"><?php echo $critical_threats; ?></div>
        </div>
    </div>

    <?php foreach ($reports as $report): ?>
        <div class="scan-card" style="border-left: 5px solid <?php echo $report['threat_level'] == 'CRITICAL' ? '#ff3366' : '#ffcc00'; ?>">
            <div class="stats">
                <span style="color: #ff3366;">[<?php echo $report['threat_level']; ?>]</span>
                <span>SHA-256: <small><?php echo substr($report['sha256_hash'], 0, 16); ?>...</small></span>
                <span>Prob: <?php echo round($report['malware_probability'] * 100, 1); ?>%</span>
            </div>
            <h3>File: <?php echo $report['file_name']; ?></h3>
            
            <table>
                <tr>
                    <th>Entropy</th><th>Strings</th><th>Imports</th><th>Sections</th>
                </tr>
                <tr>
                    <td><?php echo $report['entropy_score']; ?></td>
                    <td><?php echo $report['num_strings']; ?></td>
                    <td><?php echo $report['import_count']; ?></td>
                    <td><?php echo $report['section_count']; ?></td>
                </tr>
            </table>
        </div>
    <?php endforeach; ?>
</div>
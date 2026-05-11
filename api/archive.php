<?php
session_start();
require_once 'db_config.php';

if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit(); }

// Handle Restore Action
if (isset($_GET['restore_id'])) {
    $stmt = $pdo->prepare("UPDATE malware_reports SET is_archived = 0 WHERE report_id = ?");
    $stmt->execute([$_GET['restore_id']]);
    header("Location: archive.php");
    exit();
}

// Fetch only archived reports
$stmt = $pdo->query("SELECT r.*, f.full_feature_json FROM malware_reports r 
                     LEFT JOIN malware_features f ON r.report_id = f.report_id 
                     WHERE r.is_archived = 1
                     ORDER BY r.captured_at DESC");
$reports = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aegis-AI | Forensic Archive</title>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code&family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles.css">
</head>
<body>

   <?php
    // Query to count the number of archived forensic records
    $archiveCountStmt = $pdo->query("SELECT COUNT(*) FROM malware_reports WHERE is_archived = 1");
    $archiveCount = $archiveCountStmt->fetchColumn();
    ?>

    <div class="sidebar">
        <div class="sidebar-brand">AEGIS-AI ARCHIVE</div>
        
        <a href="index.php" class="nav-link">
            DASHBOARD
        </a>
        
        <a href="archive.php" class="nav-link active" style="display: flex; justify-content: space-between; align-items: center;">
            <span>ARCHIVE</span>
            <span style="font-family: 'Fira Code'; font-size: 0.8em; color: #52525b; border: 1px solid #27272a; padding: 2px 6px; border-radius: 4px;">
                <?php echo $archiveCount; ?>
            </span>
        </a>

        <?php if ($_SESSION['role'] === 'root'): ?>
            <a href="manage_reports.php" class="nav-link" style="color: #ffcc00;">ROOT PANEL</a>
        <?php endif; ?>
        
        <a href="index.php?logout=1" class="nav-link" style="margin-top: 40px; color: #ff4d4d;">EXIT SYSTEM</a>
    </div>

    <div class="main">
        <header style="margin-bottom: 40px;">
            <h1 style="margin: 0; color: #888;">Cold Storage Vault</h1>
            <p style="color: #444; font-size: 0.9em; font-family: 'Fira Code';">Accessing historical malware artifacts...</p>
        </header>

        <section class="glass-panel" style="padding: 0;">
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: #0d0d0f;">
                        <th style="text-align: left; padding: 15px; font-size: 0.7em; color: #52525b; text-transform: uppercase;">File Identity</th>
                        <th style="text-align: left; padding: 15px; font-size: 0.7em; color: #52525b; text-transform: uppercase;">Status</th>
                        <th style="text-align: left; padding: 15px; font-size: 0.7em; color: #52525b; text-transform: uppercase;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($reports)): ?>
                        <tr><td colspan="3" style="padding: 40px; text-align: center; color: #333; font-family: 'Fira Code';">ARCHIVE_EMPTY // NO_HISTORICAL_DATA</td></tr>
                    <?php endif; ?>
                    
                    <?php foreach ($reports as $r): 
                        $features = json_decode($r['full_feature_json'], true);
                    ?>
                    <tr>
                        <td style="padding: 15px; border-bottom: 1px solid #18181b;">
                            <div style="font-weight: 600; color: #888;"><?php echo htmlspecialchars($r['file_name']); ?></div>
                            <div style="font-size: 0.7em; font-family: 'Fira Code'; color: #333;"><?php echo substr($r['sha256_hash'], 0, 32); ?>...</div>
                        </td>
                        <td>
                            <span class="status-badge status-<?php echo $r['threat_level']; ?>" style="opacity: 0.6;">
                                <?php echo $r['threat_level']; ?>
                            </span>
                        </td>
                        <td>
                            <button onclick="toggleFeatures(<?php echo $r['report_id']; ?>)" class="action-btn">DNA</button>
                            
                            <a href="manage_reports.php?action=restore&id=<?php echo $r['report_id']; ?>" class="action-btn" style="color: #00d4ff; border-color: #00d4ff;">
                                RESTORE
                            </a>

                            <a href="manage_reports.php?action=delete&id=<?php echo $r['report_id']; ?>" 
                            class="action-btn" 
                            style="color: #ff4d4d; border-color: #441111;"
                            onclick="return confirm('PERMANENT PURGE: Delete forensic DNA artifacts for this hash?')">
                            DELETE
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <td colspan="3" style="padding: 0; border: none;">
                            <div id="features-<?php echo $r['report_id']; ?>" class="dna-grid" style="display: none;">
                                <?php if ($features): foreach ($features as $name => $value): ?>
                                    <div class="dna-node">
                                        <div class="dna-label"><?php echo $name; ?></div>
                                        <div class="dna-value"><?php echo is_numeric($value) ? round($value, 4) : $value; ?></div>
                                    </div>
                                <?php endforeach; endif; ?>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </section>
    </div>

    <script>
    function toggleFeatures(id) {
        var x = document.getElementById("features-" + id);
        x.style.display = (x.style.display === "grid") ? "none" : "grid";
    }
    </script>
</body>
</html>
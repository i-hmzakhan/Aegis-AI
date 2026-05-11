<?php
session_start();
require_once 'db_config.php';

// 1. STRICT RBAC CHECK: Only Root can access this page
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'root') {
    header("Location: index.php");
    exit();
}

// 2. HANDLE CRUD ACTIONS
if (isset($_GET['action'])) {
    $report_id = $_GET['id'];
    
    if ($_GET['action'] === 'delete') {
        // Cascade delete ensures features are also purged
        $stmt = $pdo->prepare("DELETE FROM malware_reports WHERE report_id = ?");
        $stmt->execute([$report_id]);
    } 
    elseif ($_GET['action'] === 'override') {
        $new_level = $_GET['level'];
        $stmt = $pdo->prepare("UPDATE malware_reports SET threat_level = ? WHERE report_id = ?");
        $stmt->execute([$new_level, $report_id]);
    }
    header("Location: manage_reports.php");
    exit();
}

// 3. FETCH ALL REPORTS
$reports = $pdo->query("SELECT * FROM malware_reports ORDER BY captured_at DESC")->fetchAll();

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aegis-AI | Admin Command</title>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code&family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body { background: #0f0f12; color: #e6e6e6; font-family: 'Inter', sans-serif; margin: 0; display: flex; }
        
        /* Unified Sidebar */
        .sidebar { width: 260px; height: 100vh; background: #0d0d0d; border-right: 1px solid #222; position: fixed; padding: 30px 20px; box-sizing: border-box; }
        .sidebar-brand { font-size: 10px; font-family: 'Fira Code', monospace; color: #00d4ff; letter-spacing: 3px; margin-bottom: 40px; }
        .nav-link { color: #888; text-decoration: none; display: block; padding: 12px 0; font-size: 0.9em; transition: 0.3s; }
        .nav-link:hover { color: #fff; }
        .nav-link.active { color: #ffcc00; font-weight: bold; }

        .main { margin-left: 260px; width: calc(100% - 260px); padding: 40px; box-sizing: border-box; }
        
        /* Command Table */
        .admin-card { background: rgba(20, 20, 20, 0.85); border: 1px solid #333; border-radius: 12px; padding: 25px; backdrop-filter: blur(10px); }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; color: #555; font-size: 0.7em; text-transform: uppercase; padding: 15px; border-bottom: 1px solid #222; }
        td { padding: 15px; border-bottom: 1px solid #1a1a1a; font-size: 0.85em; }

        /* Status & Actions */
        .status-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75em; font-family: 'Fira Code'; font-weight: bold; }
        .status-CRITICAL { background: rgba(255, 77, 77, 0.1); color: #ff4d4d; border: 1px solid #ff4d4d; }
        .status-CLEAN { background: rgba(16, 185, 129, 0.1); color: #10b981; border: 1px solid #10b981; }
        
        .action-btn { background: #1a1a1a; border: 1px solid #333; color: #888; padding: 6px 12px; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 0.8em; margin-right: 5px; transition: 0.2s; }
        .action-btn:hover { border-color: #00d4ff; color: #fff; }
        .btn-purge { border-color: #441111; color: #884444; }
        .btn-purge:hover { background: #ff4d4d; border-color: #ff4d4d; color: #000; }
        
        .override-select { background: #0d0d0d; color: #00d4ff; border: 1px solid #333; padding: 5px; font-size: 0.8em; border-radius: 4px; }
    </style>
</head>
<body>

    <div class="sidebar">
        <div class="sidebar-brand">AEGIS-AI ADMIN</div>
        <a href="index.php" class="nav-link">← BACK TO DASHBOARD</a>
        <a href="#" class="nav-link active">MANAGE REPORTS</a>
        <a href="#" class="nav-link">USER POLICIES</a>
        <a href="index.php?logout=1" class="nav-link" style="margin-top: 40px; color: #ff4d4d;">EXIT SYSTEM</a>
    </div>

    <div class="main">
        <header style="margin-bottom: 30px;">
            <h1 style="margin: 0; color: #ffcc00;">Policy Command Center</h1>
            <p style="color: #666; font-size: 0.9em;">Manual forensic overrides and database maintenance.</p>
        </header>

        <div class="admin-card">
            <table>
                <thead>
                    <tr>
                        <th>Binary Identity</th>
                        <th>AI Verdict</th>
                        <th>Manual Override</th>
                        <th>Database Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($reports as $r): ?>
                    <tr>
                        <td>
                            <div style="font-weight: bold;"><?php echo htmlspecialchars($r['file_name']); ?></div>
                            <div style="font-family: 'Fira Code'; font-size: 0.7em; color: #444;"><?php echo $r['sha256_hash']; ?></div>
                        </td>
                        <td>
                            <span class="status-badge status-<?php echo $r['threat_level']; ?>">
                                <?php echo $r['threat_level']; ?>
                            </span>
                        </td>
                        <td>
                            <select class="override-select" onchange="location.href='manage_reports.php?action=override&id=<?php echo $r['report_id']; ?>&level='+this.value">
                                <option value="CLEAN" <?php if($r['threat_level']=='CLEAN') echo 'selected'; ?>>CLEAN</option>
                                <option value="SUSPICIOUS" <?php if($r['threat_level']=='SUSPICIOUS') echo 'selected'; ?>>SUSPICIOUS</option>
                                <option value="CRITICAL" <?php if($r['threat_level']=='CRITICAL') echo 'selected'; ?>>CRITICAL</option>
                            </select>
                        </td>
                        <td>
                            <a href="manage_reports.php?action=delete&id=<?php echo $r['report_id']; ?>" 
                               class="action-btn btn-purge" 
                               onclick="return confirm('CRITICAL: Purge forensic DNA and reports for this hash?')">
                               PURGE
                            </a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <footer style="margin-top: 40px; text-align: right;">
            <p style="font-family: 'Fira Code'; font-size: 0.7em; color: #333;">ROOT_ACCESS_LOGGED // SID: <?php echo session_id(); ?></p>
        </footer>
    </div>

</body>
</html>
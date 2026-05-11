<?php
session_start();
require_once 'db_config.php';

// 1. HANDLE LOGIN
if (isset($_POST['login'])) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    $stmt->execute([$_POST['user'], $_POST['pass']]);
    $user = $stmt->fetch();
    if ($user) {
        $_SESSION['user_id'] = $user['user_id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
    } else { $error = "Invalid credentials!"; }
}

// 2. HANDLE LOGOUT
if (isset($_GET['logout'])) { session_destroy(); header("Location: index.php"); exit(); }

// 3. SHOW LOGIN FORM IF NOT LOGGED IN
if (!isset($_SESSION['user_id'])): ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Aegis-AI | Secure Login</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body class="login-page">
    <div class="glass-panel" style="width: 350px; padding: 40px;">
        <div class="scan-line"></div> 
        <div style="text-align: center; margin-bottom: 20px;">
            <div class="sidebar-brand" style="margin-bottom: 10px;">AEGIS-AI v3.3.0</div>
            <h2 style="margin: 0; letter-spacing: 1px;">Forensic Vault</h2>
        </div>
        <form method="POST">
            <input type="text" name="user" placeholder="Username" required 
                   style="display: block; width: 100%; margin: 15px 0; padding: 12px; background: #1a1a1a; border: 1px solid #333; color: white; border-radius: 6px; box-sizing: border-box;">
            <input type="password" name="pass" placeholder="Password" required
                   style="display: block; width: 100%; margin: 15px 0; padding: 12px; background: #1a1a1a; border: 1px solid #333; color: white; border-radius: 6px; box-sizing: border-box;">
            <button type="submit" name="login" class="btn-action" style="width: 100%;">AUTHENTICATE</button>
        </form>
        <?php if(isset($error)) echo "<p style='color:#ff4d4d; font-size: 0.8em; text-align: center; font-family:\"Fira Code\"'>$error</p>"; ?>
    </div>
</body>
</html>
<?php exit(); endif; ?>

<?php
# UPDATE: Fetch only NON-ARCHIVED reports for the Dashboard
$stmt = $pdo->query("SELECT r.*, f.full_feature_json FROM malware_reports r 
                     LEFT JOIN malware_features f ON r.report_id = f.report_id 
                     WHERE r.is_archived = 0
                     ORDER BY r.captured_at DESC LIMIT 10");
$reports = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aegis-AI | Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code&family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles.css">
</head>
<body>

    <div class="sidebar">
        <div class="sidebar-brand">AEGIS-AI FORENSICS</div>
        <a href="index.php" class="nav-link active">DASHBOARD</a>
        <?php if ($_SESSION['role'] === 'root'): ?>
            <a href="manage_reports.php" class="nav-link" style="color: #ffcc00;">ROOT PANEL</a>
        <?php endif; ?>
        <a href="?logout=1" class="nav-link" style="margin-top: 40px; color: #ff4d4d;">EXIT SYSTEM</a>
    </div>

    <div class="main">
        <header>
            <div>
                <h1 style="margin: 0; letter-spacing: -1px;">Operational Intel</h1>
                <p style="color: #52525b; margin-top: 5px; font-size: 0.9em;">
                    User: <span style="color:#eee"><?php echo $_SESSION['username']; ?></span> | 
                    Status: <span class="status-clean" style="border:none; background:none; padding:0;">ONLINE</span>
                </p>
            </div>
            <div class="status-badge status-CLEAN" style="display: flex; align-items: center; gap: 8px;">
                <div class="pulse-glow" style="width: 8px; height: 8px; background: #10b981; border-radius: 50%;"></div>
                SYSTEM STABLE
            </div>
        </header>

        <section class="glass-panel drop-zone" onclick="document.getElementById('file-upload').click()">
            <div class="scan-line"></div>
            <div style="font-size: 2.5em; margin-bottom: 10px;">📁</div>
            <h3 style="margin: 0; letter-spacing: 1px; font-family: 'Inter';">INGEST NEW BINARY</h3>
            <p style="color: #52525b; font-size: 0.8em; font-family: 'Fira Code'; margin-top: 5px;">
                AI Engine v3.0 // Ready for PE payload...
            </p>
            
            <form action="process_scan.php" method="POST" enctype="multipart/form-data" id="upload-form">
                <input type="file" name="malware_sample" id="file-upload" style="display: none;" onchange="document.getElementById('upload-form').submit()">
            </form>
        </section>

        <section class="glass-panel" style="padding: 0;">
            <div style="padding: 20px; border-bottom: 1px solid #27272a;">
                <h3 style="margin: 0; font-size: 1.1em;">Threat Ledger</h3>
            </div>
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: #0d0d0f;">
                        <th style="text-align: left; padding: 15px; font-size: 0.7em; color: #52525b; text-transform: uppercase; letter-spacing: 1px;">File Identity</th>
                        <th style="text-align: left; padding: 15px; font-size: 0.7em; color: #52525b; text-transform: uppercase; letter-spacing: 1px;">AI Verdict</th>
                        <th style="text-align: left; padding: 15px; font-size: 0.7em; color: #52525b; text-transform: uppercase; letter-spacing: 1px;">Entropy</th>
                        <th style="text-align: left; padding: 15px; font-size: 0.7em; color: #52525b; text-transform: uppercase; letter-spacing: 1px;">Forensics</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($reports as $r): 
                        $features = json_decode($r['full_feature_json'], true);
                    ?>
                    <tr>
                        <td style="padding: 15px; border-bottom: 1px solid #18181b;">
                            <div style="font-weight: 600; color: #eee;"><?php echo htmlspecialchars($r['file_name']); ?></div>
                            <div style="font-size: 0.7em; font-family: 'Fira Code'; color: #3f3f46; margin-top: 4px;">
                                <?php echo substr($r['sha256_hash'], 0, 32); ?>...
                            </div>
                        </td>
                        <td style="padding: 15px; border-bottom: 1px solid #18181b;">
                            <span class="status-badge status-<?php echo $r['threat_level']; ?>">
                                <?php echo $r['threat_level']; ?>
                            </span>
                        </td>
                        <td style="padding: 15px; border-bottom: 1px solid #18181b; font-family: 'Fira Code'; color: var(--electric-blue);">
                            <?php echo round($r['entropy_score'], 2); ?>
                        </td>
                        <td style="padding: 15px; border-bottom: 1px solid #18181b;">
                            <button onclick="toggleFeatures(<?php echo $r['report_id']; ?>)" 
                                    style="background: #1a1a1e; border: 1px solid #27272a; color: #a1a1aa; cursor: pointer; padding: 6px 12px; border-radius: 4px; font-size: 0.8em; transition: 0.2s; margin-right: 5px;">
                                DNA View
                            </button>
                            
                        </td>
                    </tr>
                    <tr>
                        <td colspan="4" style="padding: 0; border: none;">
                            <div id="features-<?php echo $r['report_id']; ?>" class="dna-grid" style="display: none;">
                                <?php if ($features): foreach ($features as $name => $value): ?>
                                    <div class="dna-node">
                                        <div class="dna-label"><?php echo htmlspecialchars($name); ?></div>
                                        <div class="dna-value"><?php echo is_numeric($value) ? round($value, 4) : htmlspecialchars($value); ?></div>
                                    </div>
                                <?php endforeach; else: ?>
                                    <p style="grid-column: 1/-1; padding: 20px; color: #3f3f46; font-family: 'Fira Code'; font-size: 0.8em;">[!] NO FORENSIC DNA ARTIFACTS FOUND</p>
                                <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </section>

        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #18181b; display: flex; justify-content: space-between;">
            <div style="font-family: 'Fira Code'; font-size: 0.7em; color: #3f3f46;">AEGIS_AI // BINARY_TRIAGE_TERMINAL</div>
            <div style="font-family: 'Fira Code'; font-size: 0.7em; color: #3f3f46;">SESSION_ID: <?php echo substr(session_id(), 0, 12); ?>...</div>
        </footer>
    </div>

    <script>
    function toggleFeatures(id) {
        var x = document.getElementById("features-" + id);
        if (x.style.display === "grid") {
            x.style.display = "none";
        } else {
            x.style.display = "grid";
        }
    }
    </script>
</body>
</html>
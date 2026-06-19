<?php
// api.php
// Main API controller for MythBrain SPA - Handles all JSON requests and hardware communications

session_start();
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/cache.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit;
}

$db = getDB();
$action = $_GET['action'] ?? '';

// Helpers
function returnSuccess($data = []) {
    echo json_encode(array_merge(['status' => 'success'], $data));
    exit;
}

function returnError($message, $code = 400) {
    http_response_code($code);
    echo json_encode(['status' => 'error', 'message' => $message]);
    exit;
}

function getRequestData() {
    $input = file_get_contents('php://input');
    return json_decode($input, true) ?? $_POST;
}

function checkAuth() {
    if (!isset($_SESSION['user_id'])) {
        returnError('Unauthorized access', 401);
    }
    return [
        'id' => $_SESSION['user_id'],
        'name' => $_SESSION['name'],
        'email' => $_SESSION['email'],
        'role' => $_SESSION['role']
    ];
}

function getOrCreateUserSettings($userId, $db) {
    $stmt = $db->prepare("SELECT * FROM user_settings WHERE user_id = ?");
    $stmt->execute([$userId]);
    $settings = $stmt->fetch();
    if (!$settings) {
        $stmt = $db->prepare("INSERT INTO user_settings (user_id, deepgram_api_key, groq_api_key, groq_model, max_response_tokens, temperature, transcription_language) VALUES (?, ?, ?, ?, ?, ?, 'multi')");
        $stmt->execute([
            $userId,
            getenv('DEEPGRAM_API_KEY'),
            getenv('GROQ_API_KEY'),
            getenv('GROQ_MODEL') ?: 'openai/gpt-oss-120b',
            intval(getenv('MAX_RESPONSE_TOKENS') ?: 1024),
            0.7
        ]);
        $stmt = $db->prepare("SELECT * FROM user_settings WHERE user_id = ?");
        $stmt->execute([$userId]);
        $settings = $stmt->fetch();
    }
    return $settings;
}

// Global Maintenance Check for standard users
$stmtAdmin = $db->query("SELECT setting_value FROM site_settings WHERE setting_key = 'admin_maintenance'");
$adminMaintVal = (int)($stmtAdmin->fetchColumn() ?: 0);
$isAdminMaintenance = ($adminMaintVal === 1);
$isUserAdmin = (isset($_SESSION['role']) && $_SESSION['role'] === 'admin');

if ($isAdminMaintenance && !$isUserAdmin && !in_array($action, ['login', 'check_auth', 'esp_ping', 'esp_upload_chunk'])) {
    returnError('System is currently under maintenance. Please try again later.', 503);
}

switch ($action) {

    // ==========================================
    // AUTHENTICATION ENDPOINTS
    // ==========================================
    
    case 'register':
        $data = getRequestData();
        $name = trim($data['name'] ?? '');
        $email = trim($data['email'] ?? '');
        $password = $data['password'] ?? '';
        
        if (empty($name) || empty($email) || empty($password)) {
            returnError('Please fill in all fields.');
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            returnError('Invalid email format.');
        }
        
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $vToken = bin2hex(random_bytes(16));
        $vExpire = date('Y-m-d H:i:s', time() + 3600); // 1 hour
        
        try {
            $db->beginTransaction();
            $stmt = $db->prepare("INSERT INTO users (name, email, password, role, is_verified, verification_token, verification_expires) VALUES (?, ?, ?, 'user', 1, ?, ?)");
            // Note: Auto-verified to facilitate easy testing in local workspace
            $stmt->execute([$name, $email, $hashedPassword, $vToken, $vExpire]);
            $userId = $db->lastInsertId();
            
            // Create user settings
            getOrCreateUserSettings($userId, $db);
            
            $db->commit();
            returnSuccess(['message' => 'Account created successfully!']);
        } catch (PDOException $e) {
            $db->rollBack();
            if ($e->getCode() == 23000) {
                returnError('Email is already registered.');
            }
            returnError('Registration failed: ' . $e->getMessage());
        }
        break;
        
    case 'login':
        $data = getRequestData();
        $email = trim($data['email'] ?? '');
        $password = $data['password'] ?? '';
        
        if (empty($email) || empty($password)) {
            returnError('Please fill in all fields.');
        }
        
        $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['name'] = $user['name'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['role'] = $user['role'];
            
            // Generate/Ensure settings
            getOrCreateUserSettings($user['id'], $db);

            returnSuccess([
                'user' => [
                    'id' => $user['id'],
                    'name' => $user['name'],
                    'email' => $user['email'],
                    'role' => $user['role'],
                    'profile_picture' => $user['profile_picture']
                ]
            ]);
        } else {
            returnError('Invalid email or password.');
        }
        break;

    case 'forgot':
        $data = getRequestData();
        $email = trim($data['email'] ?? '');
        if (empty($email)) {
            returnError('Please enter your email address.');
        }
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        
        if ($user) {
            $resetToken = bin2hex(random_bytes(16));
            $resetExpire = date('Y-m-d H:i:s', time() + 1800); // 30 mins
            $update = $db->prepare("UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?");
            $update->execute([$resetToken, $resetExpire, $user['id']]);
            
            // Mock email simulation
            returnSuccess(['message' => 'Password reset link sent to your email. (Simulated token: ' . $resetToken . ')', 'token' => $resetToken]);
        } else {
            returnSuccess(['message' => 'Password reset link sent if the email exists.']);
        }
        break;
        
    case 'verify_email':
        $data = getRequestData();
        $token = trim($data['token'] ?? '');
        if (empty($token)) {
            returnError('Verification token missing.');
        }
        $stmt = $db->prepare("SELECT id FROM users WHERE verification_token = ?");
        $stmt->execute([$token]);
        $user = $stmt->fetch();
        if ($user) {
            $update = $db->prepare("UPDATE users SET is_verified = 1, verification_token = NULL, verification_expires = NULL WHERE id = ?");
            $update->execute([$user['id']]);
            returnSuccess(['message' => 'Email verified successfully!']);
        } else {
            returnError('Invalid verification token.');
        }
        break;
        
    case 'reset_password':
        $data = getRequestData();
        $token = trim($data['token'] ?? '');
        $password = $data['password'] ?? '';
        if (empty($token) || empty($password)) {
            returnError('Missing fields.');
        }
        $stmt = $db->prepare("SELECT id, reset_expires FROM users WHERE reset_token = ?");
        $stmt->execute([$token]);
        $user = $stmt->fetch();
        if ($user) {
            if (strtotime($user['reset_expires']) < time()) {
                returnError('Reset link expired.');
            }
            $hashed = password_hash($password, PASSWORD_DEFAULT);
            $update = $db->prepare("UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?");
            $update->execute([$hashed, $user['id']]);
            returnSuccess(['message' => 'Password reset successfully!']);
        } else {
            returnError('Invalid or expired reset token.');
        }
        break;

    case 'logout':
        session_destroy();
        returnSuccess(['message' => 'Logged out successfully']);
        break;
        
    case 'check_auth':
        if (isset($_SESSION['user_id'])) {
            $stmt = $db->prepare("SELECT name, email, role, profile_picture FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $userData = $stmt->fetch();
            if ($userData) {
                returnSuccess([
                    'authenticated' => true,
                    'user' => [
                        'id' => $_SESSION['user_id'],
                        'name' => $userData['name'],
                        'email' => $userData['email'],
                        'role' => $userData['role'],
                        'profile_picture' => $userData['profile_picture']
                    ],
                    'cache_status' => Cache::getStatus(),
                    'redis_active' => Cache::isRedisActive()
                ]);
            }
        }
        returnSuccess([
            'authenticated' => false,
            'cache_status' => Cache::getStatus(),
            'redis_active' => Cache::isRedisActive()
        ]);
        break;
        
    case 'update_user_profile':
        $user = checkAuth();
        $data = getRequestData();
        $name = trim($data['name'] ?? '');
        if (empty($name)) {
            returnError('Name cannot be empty.');
        }
        
        $profilePictureBase64 = $data['profile_picture'] ?? null;
        $profilePicturePath = null;
        
        if (!empty($profilePictureBase64) && strpos($profilePictureBase64, 'data:image') === 0) {
            // Save base64 image
            if (preg_match('/^data:image\/(\w+);base64,/', $profilePictureBase64, $type)) {
                $imgData = substr($profilePictureBase64, strpos($profilePictureBase64, ',') + 1);
                $type = strtolower($type[1]);
                if (in_array($type, ['jpg', 'jpeg', 'png', 'webp'])) {
                    $imgData = base64_decode($imgData);
                    $uploadsDir = __DIR__ . '/uploads/avatars';
                    if (!is_dir($uploadsDir)) {
                        @mkdir($uploadsDir, 0777, true);
                    }
                    $fileName = 'avatar_' . $user['id'] . '_' . uniqid() . '.' . $type;
                    $filePath = $uploadsDir . '/' . $fileName;
                    if (file_put_contents($filePath, $imgData)) {
                        $profilePicturePath = 'uploads/avatars/' . $fileName;
                    }
                }
            }
        }
        
        if ($profilePicturePath) {
            $stmt = $db->prepare("UPDATE users SET name = ?, profile_picture = ? WHERE id = ?");
            $stmt->execute([$name, $profilePicturePath, $user['id']]);
        } else {
            $stmt = $db->prepare("UPDATE users SET name = ? WHERE id = ?");
            $stmt->execute([$name, $user['id']]);
        }
        
        $_SESSION['name'] = $name;
        returnSuccess(['message' => 'Profile updated successfully!', 'profile_picture' => $profilePicturePath]);
        break;

    // ==========================================
    // DEVICE CONFIGURATION ENDPOINTS
    // ==========================================
    
    case 'get_devices':
        $user = checkAuth();
        $stmt = $db->prepare("SELECT * FROM devices WHERE user_id = ? ORDER BY id DESC");
        $stmt->execute([$user['id']]);
        returnSuccess(['devices' => $stmt->fetchAll()]);
        break;
        
    case 'add_device':
        $user = checkAuth();
        $data = getRequestData();
        $token = strtoupper(trim($data['token'] ?? ''));
        
        if (strlen($token) !== 5) {
            returnError('Device token must be exactly 5 characters.');
        }
        
        // Find pre-seeded device by token
        $stmt = $db->prepare("SELECT * FROM devices WHERE token = ?");
        $stmt->execute([$token]);
        $device = $stmt->fetch();
        
        if (!$device) {
            returnError('Device token not recognized. Please check the token pre-installed in your ESP32 code.');
        }
        
        if ($device['user_id'] !== null) {
            returnError('This device token is already linked to another account.');
        }
        
        // Link device permanently
        $stmt = $db->prepare("UPDATE devices SET user_id = ? WHERE token = ?");
        $stmt->execute([$user['id'], $token]);
        
        returnSuccess(['message' => 'Device activated and linked successfully!', 'device' => $device]);
        break;
        
    case 'remove_device':
        $user = checkAuth();
        $data = getRequestData();
        $deviceId = (int)($data['device_id'] ?? 0);
        
        $stmt = $db->prepare("UPDATE devices SET user_id = NULL, recording_state = 0 WHERE id = ? AND user_id = ?");
        $stmt->execute([$deviceId, $user['id']]);
        
        returnSuccess(['message' => 'Device unlinked successfully.']);
        break;
        
    case 'update_device_wifi':
        $user = checkAuth();
        $data = getRequestData();
        $deviceId = (int)($data['device_id'] ?? 0);
        
        $wifi1_ssid = trim($data['wifi_1_ssid'] ?? '');
        $wifi1_pass = trim($data['wifi_1_password'] ?? '');
        $wifi2_ssid = trim($data['wifi_2_ssid'] ?? '');
        $wifi2_pass = trim($data['wifi_2_password'] ?? '');
        $wifi3_ssid = trim($data['wifi_3_ssid'] ?? '');
        $wifi3_pass = trim($data['wifi_3_password'] ?? '');
        $wifi4_ssid = trim($data['wifi_4_ssid'] ?? '');
        $wifi4_pass = trim($data['wifi_4_password'] ?? '');
        $wifi5_ssid = trim($data['wifi_5_ssid'] ?? '');
        $wifi5_pass = trim($data['wifi_5_password'] ?? '');
        
        if (empty($wifi1_ssid)) {
            returnError('At least 1 Wi-Fi network SSID is compulsory.');
        }
        
        $stmt = $db->prepare("
            UPDATE devices 
            SET wifi_1_ssid = ?, wifi_1_password = ?, wifi_2_ssid = ?, wifi_2_password = ?, wifi_3_ssid = ?, wifi_3_password = ?, wifi_4_ssid = ?, wifi_4_password = ?, wifi_5_ssid = ?, wifi_5_password = ?
            WHERE id = ? AND user_id = ?
        ");
        $stmt->execute([
            $wifi1_ssid, $wifi1_pass,
            empty($wifi2_ssid) ? null : $wifi2_ssid, empty($wifi2_ssid) ? null : $wifi2_pass,
            empty($wifi3_ssid) ? null : $wifi3_ssid, empty($wifi3_ssid) ? null : $wifi3_pass,
            empty($wifi4_ssid) ? null : $wifi4_ssid, empty($wifi4_ssid) ? null : $wifi4_pass,
            empty($wifi5_ssid) ? null : $wifi5_ssid, empty($wifi5_ssid) ? null : $wifi5_pass,
            $deviceId, $user['id']
        ]);
        
        returnSuccess(['message' => 'Wi-Fi credentials updated. Device will sync on its next check.']);
        break;

    case 'change_device_token':
        $user = checkAuth();
        $data = getRequestData();
        $deviceId = (int)($data['device_id'] ?? 0);
        $newToken = strtoupper(trim($data['new_token'] ?? ''));
        
        if (strlen($newToken) !== 5) {
            returnError('New device token must be exactly 5 characters.');
        }
        
        // Verify user owns the device
        $stmt = $db->prepare("SELECT * FROM devices WHERE id = ? AND user_id = ?");
        $stmt->execute([$deviceId, $user['id']]);
        $device = $stmt->fetch();
        if (!$device) {
            returnError('Device not found or not owned by you.');
        }
        
        // Ensure new token is unique
        $stmt = $db->prepare("SELECT id FROM devices WHERE token = ? AND id != ?");
        $stmt->execute([$newToken, $deviceId]);
        if ($stmt->fetch()) {
            returnError('This token is already in use by another device.');
        }
        
        $stmt = $db->prepare("UPDATE devices SET token = ? WHERE id = ?");
        $stmt->execute([$newToken, $deviceId]);
        
        returnSuccess(['message' => 'Device activation token changed successfully. Please update your hardware firmware with token: ' . $newToken]);
        break;

    case 'toggle_recording':
        $user = checkAuth();
        $data = getRequestData();
        $deviceId = (int)($data['device_id'] ?? 0);
        
        $stmt = $db->prepare("SELECT * FROM devices WHERE id = ? AND user_id = ?");
        $stmt->execute([$deviceId, $user['id']]);
        $device = $stmt->fetch();
        
        if (!$device) {
            returnError('Device not found.');
        }
        
        $newState = ($device['recording_state'] == 1) ? 0 : 1;
        
        $db->beginTransaction();
        try {
            $stmt = $db->prepare("UPDATE devices SET recording_state = ? WHERE id = ?");
            $stmt->execute([$newState, $deviceId]);
            
            if ($newState == 1) {
                // Toggled ON: Create new recording
                $title = 'Meeting on ' . date('d-m-Y H:i:s');
                $date = date('Y-m-d');
                $start = date('Y-m-d H:i:s');
                
                $stmtRec = $db->prepare("INSERT INTO recordings (user_id, device_token, title, date, start_time, status) VALUES (?, ?, ?, ?, ?, 'recording')");
                $stmtRec->execute([$user['id'], $device['token'], $title, $date, $start]);
                $recordingId = $db->lastInsertId();
                
                // Clear active transcript cache
                Cache::delete('active_transcript_' . $user['id']);
                Cache::delete('active_rec_meta_' . $user['id']);
                
                $db->commit();
                returnSuccess(['recording_state' => 1, 'recording_id' => $recordingId, 'message' => 'Recording started.']);
            } else {
                // Toggled OFF: Mark recording as finishing (waiting for ESP32 queue to empty)
                $stmtRec = $db->prepare("SELECT id FROM recordings WHERE user_id = ? AND device_token = ? AND status = 'recording' ORDER BY id DESC LIMIT 1");
                $stmtRec->execute([$user['id'], $device['token']]);
                $recording = $stmtRec->fetch();
                
                if ($recording) {
                    $stmtUpdate = $db->prepare("UPDATE recordings SET status = 'finishing' WHERE id = ?");
                    $stmtUpdate->execute([$recording['id']]);
                }
                
                // Clear active transcript cache
                Cache::delete('active_transcript_' . $user['id']);
                Cache::delete('active_rec_meta_' . $user['id']);
                
                $db->commit();
                returnSuccess(['recording_state' => 0, 'message' => 'Recording stopping. Finalizing data sync...']);
            }
        } catch (Exception $e) {
            $db->rollBack();
            returnError('Failed to toggle recording: ' . $e->getMessage());
        }
        break;
    case 'force_complete_recording':
        $user = checkAuth();
        $data = getRequestData();
        $deviceId = (int)($data['device_id'] ?? 0);
        
        $stmt = $db->prepare("SELECT * FROM devices WHERE id = ? AND user_id = ?");
        $stmt->execute([$deviceId, $user['id']]);
        $device = $stmt->fetch();
        
        if (!$device) {
            returnError('Device not found.');
        }
        
        // Find active recording row in 'finishing' or 'recording' state
        $stmtRec = $db->prepare("SELECT id FROM recordings WHERE user_id = ? AND device_token = ? AND status IN ('recording', 'finishing') ORDER BY id DESC LIMIT 1");
        $stmtRec->execute([$user['id'], $device['token']]);
        $recording = $stmtRec->fetch();
        
        if ($recording) {
            $db->beginTransaction();
            try {
                // Update status to completed and log end time
                $endTime = date('Y-m-d H:i:s');
                $stmtUpdateRec = $db->prepare("UPDATE recordings SET status = 'completed', end_time = ? WHERE id = ?");
                $stmtUpdateRec->execute([$endTime, $recording['id']]);
                
                // Reset device recording state in DB
                $stmtUpdateDev = $db->prepare("UPDATE devices SET recording_state = 0 WHERE id = ?");
                $stmtUpdateDev->execute([$deviceId]);
                
                // Invalidate Redis active recording cache
                Cache::delete('active_transcript_' . $user['id']);
                Cache::delete('active_rec_meta_' . $user['id']);
                
                $db->commit();
            } catch (Exception $e) {
                $db->rollBack();
                returnError('Failed to force complete recording: ' . $e->getMessage());
            }
        }
        
        returnSuccess(['message' => 'Meeting completed successfully (forced).']);
        break;

    case 'get_active_recording':
        $user = checkAuth();
        
        // Check Redis cache first to make polling super fast
        $cacheKey = 'active_transcript_' . $user['id'];
        $metaCacheKey = 'active_rec_meta_' . $user['id'];
        
        $cachedMeta = Cache::get($metaCacheKey);
        $cachedTranscript = Cache::get($cacheKey);
        
        if ($cachedMeta !== null && $cachedTranscript !== null) {
            returnSuccess([
                'active' => !empty($cachedMeta),
                'recording' => $cachedMeta ? array_merge($cachedMeta, ['transcript' => $cachedTranscript]) : null,
                'cached' => true
            ]);
        }
        
        // Find if there is an active recording
        $stmt = $db->prepare("SELECT id, title, start_time, word_count, chunk_count, transcript, status FROM recordings WHERE user_id = ? AND status IN ('recording', 'finishing') ORDER BY id DESC LIMIT 1");
        $stmt->execute([$user['id']]);
        $rec = $stmt->fetch();
        
        if ($rec) {
            // Format Bangladeshi Time
            $rec['start_time_formatted'] = date('h:i A', strtotime($rec['start_time']));
            $elapsedSeconds = time() - strtotime($rec['start_time']);
            $rec['elapsed_seconds'] = $elapsedSeconds;
            
            // Set Redis cache (TTL 3 seconds for active polling)
            Cache::set($metaCacheKey, [
                'id' => $rec['id'],
                'title' => $rec['title'],
                'start_time' => $rec['start_time'],
                'start_time_formatted' => $rec['start_time_formatted'],
                'word_count' => $rec['word_count'],
                'chunk_count' => $rec['chunk_count'],
                'elapsed_seconds' => $elapsedSeconds,
                'status' => $rec['status']
            ], 3);
            Cache::set($cacheKey, $rec['transcript'] ?? '', 3);
            
            returnSuccess([
                'active' => true,
                'recording' => $rec
            ]);
        } else {
            Cache::set($metaCacheKey, [], 5);
            Cache::set($cacheKey, '', 5);
            returnSuccess([
                'active' => false,
                'recording' => null
            ]);
        }
        break;

    // ==========================================
    // RECORDINGS MANAGEMENT & RETRIEVAL
    // ==========================================
    
    case 'get_recordings':
        $user = checkAuth();
        $date = $_GET['date'] ?? ''; // Y-m-d format
        $search = $_GET['search'] ?? '';
        
        $query = "SELECT * FROM recordings WHERE user_id = :user_id";
        $params = [':user_id' => $user['id']];
        
        if (!empty($date)) {
            $query .= " AND date = :date";
            $params[':date'] = $date;
        }
        if (!empty($search)) {
            $query .= " AND (title LIKE :search OR transcript LIKE :search)";
            $params[':search'] = '%' . $search . '%';
        }
        
        $query .= " ORDER BY id DESC";
        
        if (empty($date) && empty($search)) {
            $query .= " LIMIT 50"; // Limit default load size
        }
        
        $stmt = $db->prepare($query);
        $stmt->execute($params);
        $recordings = $stmt->fetchAll();
        
        // Formatted date and time helper
        foreach ($recordings as &$rec) {
            $rec['start_time_formatted'] = date('h:i A', strtotime($rec['start_time']));
            $rec['date_formatted'] = date('d F, Y', strtotime($rec['date']));
            if ($rec['end_time']) {
                $rec['end_time_formatted'] = date('h:i A', strtotime($rec['end_time']));
                $rec['duration_minutes'] = round((strtotime($rec['end_time']) - strtotime($rec['start_time'])) / 60, 1);
            } else {
                $rec['end_time_formatted'] = 'Ongoing';
                $rec['duration_minutes'] = 0;
            }
        }
        
        returnSuccess(['recordings' => $recordings]);
        break;
        
    case 'get_recording_details':
        $user = checkAuth();
        $recId = (int)($_GET['id'] ?? 0);
        
        $stmt = $db->prepare("SELECT * FROM recordings WHERE id = ? AND user_id = ?");
        $stmt->execute([$recId, $user['id']]);
        $rec = $stmt->fetch();
        
        if (!$rec) {
            returnError('Recording not found.');
        }
        
        $rec['start_time_formatted'] = date('h:i A', strtotime($rec['start_time']));
        $rec['date_formatted'] = date('d F, Y', strtotime($rec['date']));
        $rec['duration_minutes'] = $rec['end_time'] ? round((strtotime($rec['end_time']) - strtotime($rec['start_time'])) / 60, 1) : 0;
        
        returnSuccess(['recording' => $rec]);
        break;
        
    case 'delete_recording':
        $user = checkAuth();
        $data = getRequestData();
        $recId = (int)($data['recording_id'] ?? 0);
        
        $stmt = $db->prepare("DELETE FROM recordings WHERE id = ? AND user_id = ?");
        $stmt->execute([$recId, $user['id']]);
        
        returnSuccess(['message' => 'Recording deleted successfully.']);
        break;
        
    case 'update_recording_title':
        $user = checkAuth();
        $data = getRequestData();
        $recId = (int)($data['recording_id'] ?? 0);
        $newTitle = trim($data['title'] ?? '');
        
        if (empty($newTitle)) {
            returnError('Title cannot be empty.');
        }
        
        $stmt = $db->prepare("UPDATE recordings SET title = ? WHERE id = ? AND user_id = ?");
        $stmt->execute([$newTitle, $recId, $user['id']]);
        
        returnSuccess(['message' => 'Recording title updated successfully.', 'title' => $newTitle]);
        break;
        
    case 'download_transcript':
        $user = checkAuth();
        $recId = (int)($_GET['id'] ?? 0);
        
        $stmt = $db->prepare("SELECT title, date, transcript FROM recordings WHERE id = ? AND user_id = ?");
        $stmt->execute([$recId, $user['id']]);
        $rec = $stmt->fetch();
        
        if (!$rec) {
            returnError('Recording not found.');
        }
        
        $filename = preg_replace('/[^a-zA-Z0-9_-]/', '_', $rec['title']) . '_' . $rec['date'] . '.txt';
        
        header('Content-Description: File Transfer');
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        
        echo "MythBrain AI Meeting Recorder - Transcript Download\n";
        echo "====================================================\n";
        echo "Meeting Title: " . $rec['title'] . "\n";
        echo "Meeting Date: " . date('d F, Y', strtotime($rec['date'])) . "\n";
        echo "====================================================\n\n";
        echo $rec['transcript'] ?: "No transcript text recorded.";
        exit;
        break;

    // ==========================================
    // AI CHAT & SUMMARIZE ENDPOINTS (GROQ)
    // ==========================================
    
    case 'ask_ai':
        $user = checkAuth();
        $data = getRequestData();
        $recId = (int)($data['recording_id'] ?? 0);
        $message = trim($data['message'] ?? '');
        
        if (empty($message)) {
            returnError('Message cannot be empty.');
        }
        
        $stmt = $db->prepare("SELECT title, date, start_time, end_time, transcript FROM recordings WHERE id = ? AND user_id = ?");
        $stmt->execute([$recId, $user['id']]);
        $rec = $stmt->fetch();
        
        if (!$rec) {
            returnError('Recording not found.');
        }
        
        $context = $rec['transcript'] ?: 'No transcript text available.';
        
        $meetingDate = date('d F, Y', strtotime($rec['date']));
        $startTime = date('h:i A', strtotime($rec['start_time']));
        $endTime = $rec['end_time'] ? date('h:i A', strtotime($rec['end_time'])) : 'Ongoing';
        
        $messages = [
            ["role" => "system", "content" => "You are MythBrain AI, a helpful virtual assistant. Answer the user's questions strictly based on the following meeting details and transcript. If the answer cannot be found or inferred from the details or transcript, politely say so. Do not make up information.\n\nMeeting Context:\nTitle: " . $rec['title'] . "\nDate: " . $meetingDate . "\nStart Time: " . $startTime . "\nEnd Time: " . $endTime . "\nTranscript:\n" . $context],
            ["role" => "user", "content" => $message]
        ];
        
        $userSettings = getOrCreateUserSettings($user['id'], $db);
        $reply = callGroqLLM($messages, $userSettings, $db);
        
        returnSuccess(['response' => $reply]);
        break;
        
    case 'myth_chat':
        $user = checkAuth();
        $data = getRequestData();
        $message = trim($data['message'] ?? '');
        
        if (empty($message)) {
            returnError('Message cannot be empty.');
        }
        
        // Retrieve all completed transcripts for the user
        $stmt = $db->prepare("SELECT title, date, transcript FROM recordings WHERE user_id = ? AND status = 'completed' AND transcript IS NOT NULL ORDER BY id DESC LIMIT 15");
        $stmt->execute([$user['id']]);
        $meetings = $stmt->fetchAll();
        
        $compiledContext = "";
        foreach ($meetings as $meet) {
            $compiledContext .= "--- Meeting: " . $meet['title'] . " on " . date('d M Y', strtotime($meet['date'])) . " ---\n";
            $compiledContext .= $meet['transcript'] . "\n\n";
        }
        
        if (empty($compiledContext)) {
            $compiledContext = "No meeting recordings recorded yet.";
        }
        
        $messages = [
            ["role" => "system", "content" => "You are MythBrain AI, an expert analytical assistant. The user wants to query their entire knowledge base of past meeting recordings. Utilize the meeting contexts below to answer the user's questions clearly, summarising across multiple meetings if needed. Identify meetings by title or date when citing facts.\n\nKnowledge Base:\n" . $compiledContext],
            ["role" => "user", "content" => $message]
        ];
        
        $userSettings = getOrCreateUserSettings($user['id'], $db);
        $reply = callGroqLLM($messages, $userSettings, $db);
        
        returnSuccess(['response' => $reply]);
        break;

    case 'regenerate_summary':
        $user = checkAuth();
        $data = getRequestData();
        $recId = (int)($data['recording_id'] ?? 0);
        
        $stmt = $db->prepare("SELECT transcript FROM recordings WHERE id = ? AND user_id = ?");
        $stmt->execute([$recId, $user['id']]);
        $rec = $stmt->fetch();
        
        if (!$rec) {
            returnError('Recording not found.');
        }
        
        $transcript = trim($rec['transcript'] ?? '');
        if (empty($transcript)) {
            returnError('Cannot generate summary for an empty transcript.');
        }
        
        $userSettings = getOrCreateUserSettings($user['id'], $db);
        $summary = generateSummary($transcript, $userSettings, $db);
        
        if ($summary) {
            $stmtUpdate = $db->prepare("UPDATE recordings SET summary = ? WHERE id = ?");
            $stmtUpdate->execute([$summary, $recId]);
            returnSuccess(['summary' => $summary, 'message' => 'Summary regenerated successfully!']);
        } else {
            returnError('Failed to generate summary via Groq.');
        }
        break;
        
    case 'get_user_settings':
        $user = checkAuth();
        $settings = getOrCreateUserSettings($user['id'], $db);
        returnSuccess(['settings' => $settings]);
        break;
        
    case 'update_user_settings':
        $user = checkAuth();
        $data = getRequestData();
        
        $dgKey = trim($data['deepgram_api_key'] ?? '');
        $groqKey = trim($data['groq_api_key'] ?? '');
        $groqModel = trim($data['groq_model'] ?? 'openai/gpt-oss-120b');
        $maxTokens = intval($data['max_response_tokens'] ?? 1024);
        $temperature = isset($data['temperature']) ? floatval($data['temperature']) : 0.7;
        $transLang = trim($data['transcription_language'] ?? 'bn');
        
        if ($maxTokens <= 0) $maxTokens = 1024;
        if ($temperature < 0.0) $temperature = 0.0;
        if ($temperature > 1.5) $temperature = 1.5;
        if (!in_array($transLang, ['bn', 'en', 'multi'])) {
            $transLang = 'bn';
        }
        
        $stmt = $db->prepare("
            UPDATE user_settings 
            SET deepgram_api_key = ?, groq_api_key = ?, groq_model = ?, max_response_tokens = ?, temperature = ?, transcription_language = ? 
            WHERE user_id = ?
        ");
        $stmt->execute([$dgKey, $groqKey, $groqModel, $maxTokens, $temperature, $transLang, $user['id']]);
        
        returnSuccess(['message' => 'API Configuration keys updated successfully.']);
        break;

    // ==========================================
    // HARDWARE API ENDPOINTS (ESP32 COMMUNICATION)
    // ==========================================
    
    case 'esp_complete_recording':
        $token = strtoupper(trim($_GET['token'] ?? ''));
        if (empty($token) || strlen($token) !== 5) {
            returnError('Invalid token format.', 400);
        }
        
        $stmt = $db->prepare("SELECT * FROM devices WHERE token = ?");
        $stmt->execute([$token]);
        $device = $stmt->fetch();
        
        if (!$device) {
            returnError('Device token not registered.', 404);
        }
        
        if ($device['user_id'] === null) {
            returnError('Device not activated or linked to a user.', 400);
        }
        
        // Find active recording row in status 'recording' or 'finishing'
        $stmtRec = $db->prepare("SELECT id, transcript FROM recordings WHERE user_id = ? AND device_token = ? AND status IN ('recording', 'finishing') ORDER BY id DESC LIMIT 1");
        $stmtRec->execute([$device['user_id'], $token]);
        $recording = $stmtRec->fetch();
        
        if (!$recording) {
            returnError('No active recording session found to complete.', 404);
        }
        
        $db->beginTransaction();
        try {
            $end = date('Y-m-d H:i:s');
            $stmtUpdate = $db->prepare("UPDATE recordings SET status = 'completed', end_time = ? WHERE id = ?");
            $stmtUpdate->execute([$end, $recording['id']]);
            
            // Clear active transcript cache
            Cache::delete('active_transcript_' . $device['user_id']);
            Cache::delete('active_rec_meta_' . $device['user_id']);
            
            $db->commit();
            returnSuccess(['message' => 'Recording completed successfully.']);
        } catch (Exception $e) {
            $db->rollBack();
            returnError('Failed to complete recording: ' . $e->getMessage(), 500);
        }
        break;
        
    case 'esp_ping':
        $token = strtoupper(trim($_GET['token'] ?? ''));
        if (empty($token) || strlen($token) !== 5) {
            returnError('Invalid token format.', 400);
        }
        
        $stmt = $db->prepare("SELECT * FROM devices WHERE token = ?");
        $stmt->execute([$token]);
        $device = $stmt->fetch();
        
        if (!$device) {
            returnError('Device token not registered.', 404);
        }
        
        // Update device heartbeat
        $now = date('Y-m-d H:i:s');
        $stmtUpdate = $db->prepare("UPDATE devices SET last_ping = ? WHERE id = ?");
        $stmtUpdate->execute([$now, $device['id']]);
        
        // Collect Wi-Fi list to send to ESP32
        $wifiList = [];
        if (!empty($device['wifi_1_ssid'])) $wifiList[] = ['ssid' => $device['wifi_1_ssid'], 'pass' => $device['wifi_1_password']];
        if (!empty($device['wifi_2_ssid'])) $wifiList[] = ['ssid' => $device['wifi_2_ssid'], 'pass' => $device['wifi_2_password']];
        if (!empty($device['wifi_3_ssid'])) $wifiList[] = ['ssid' => $device['wifi_3_ssid'], 'pass' => $device['wifi_3_password']];
        if (!empty($device['wifi_4_ssid'])) $wifiList[] = ['ssid' => $device['wifi_4_ssid'], 'pass' => $device['wifi_4_password']];
        if (!empty($device['wifi_5_ssid'])) $wifiList[] = ['ssid' => $device['wifi_5_ssid'], 'pass' => $device['wifi_5_password']];
        
        returnSuccess([
            'recording_state' => (int)$device['recording_state'],
            'wifi' => $wifiList
        ]);
        break;
        
    case 'esp_upload_chunk':
        $token = strtoupper(trim($_GET['token'] ?? ''));
        if (empty($token) || strlen($token) !== 5) {
            returnError('Invalid token format.', 400);
        }
        
        $stmt = $db->prepare("SELECT * FROM devices WHERE token = ?");
        $stmt->execute([$token]);
        $device = $stmt->fetch();
        
        if (!$device) {
            returnError('Device token not registered.', 404);
        }
        
        if ($device['user_id'] === null) {
            returnError('Device not activated or linked to a user.', 400);
        }
        
        // Find active recording row
        $stmtRec = $db->prepare("SELECT id, word_count, chunk_count, transcript FROM recordings WHERE user_id = ? AND device_token = ? AND status IN ('recording', 'finishing') ORDER BY id DESC LIMIT 1");
        $stmtRec->execute([$device['user_id'], $token]);
        $recording = $stmtRec->fetch();
        
        if (!$recording) {
            returnError('No active recording session found for this device on the server.', 404);
        }
        
        // Read raw audio from input body
        $audioData = file_get_contents('php://input');
        if (empty($audioData)) {
            returnError('No audio payload received.', 400);
        }
        
        // Save audio chunk to disk
        $dir = __DIR__ . '/uploads/recordings/' . $token;
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        $chunkNum = (int)$recording['chunk_count'] + 1;
        $audioFileName = 'chunk_' . $chunkNum . '_' . time() . '.wav';
        $audioPath = 'uploads/recordings/' . $token . '/' . $audioFileName;
        file_put_contents(__DIR__ . '/' . $audioPath, $audioData);
        
        // Transcribe audio using Deepgram
        $userSettings = getOrCreateUserSettings($device['user_id'], $db);
        $dgApiKey = $userSettings['deepgram_api_key'] ?: getenv('DEEPGRAM_API_KEY');
        $dgLang = $userSettings['transcription_language'] ?: 'multi';
        
        if (empty($dgApiKey)) {
            returnError('Deepgram API key not configured.', 500);
        }
        
        try {
            $transcriptText = callDeepgramSTT($audioData, $dgApiKey, $dgLang);
        } catch (Exception $e) {
            $errCode = $e->getCode();
            // If it's a client authentication/bad request issue (400, 401, 403), return 400.
            // Otherwise, return 500 (server/rate limit issue) so the ESP32 retries.
            $httpStatus = ($errCode >= 400 && $errCode < 405) ? 400 : 500;
            returnError($e->getMessage(), $httpStatus);
        }
        $wordCount = str_word_count($transcriptText);
        
        // Save chunk details
        $stmtChunk = $db->prepare("INSERT INTO recording_chunks (recording_id, chunk_number, audio_path, transcript) VALUES (?, ?, ?, ?)");
        $stmtChunk->execute([$recording['id'], $chunkNum, $audioPath, $transcriptText]);
        
        // Append chunk text to full transcript in DB
        $separator = empty($recording['transcript']) ? "" : " ";
        $updatedTranscript = $recording['transcript'] . $separator . $transcriptText;
        $newWordCount = (int)$recording['word_count'] + $wordCount;
        
        $stmtUpdateRec = $db->prepare("UPDATE recordings SET transcript = ?, word_count = ?, chunk_count = ? WHERE id = ?");
        $stmtUpdateRec->execute([$updatedTranscript, $newWordCount, $chunkNum, $recording['id']]);
        
        // Update user settings usage stats
        $stmtUpdateSettings = $db->prepare("UPDATE user_settings SET words_transcribed = words_transcribed + ?, chunks_sent = chunks_sent + 1 WHERE user_id = ?");
        $stmtUpdateSettings->execute([$wordCount, $device['user_id']]);
        
        // Invalidate Redis active recording cache so the frontend fetches new data
        Cache::delete('active_transcript_' . $device['user_id']);
        Cache::delete('active_rec_meta_' . $device['user_id']);
        
        returnSuccess([
            'message' => 'Chunk uploaded and processed successfully.',
            'transcript' => $transcriptText,
            'word_count' => $wordCount
        ]);
        break;

    case 'esp_complete_recording':
        $token = strtoupper(trim($_GET['token'] ?? ''));
        if (empty($token) || strlen($token) !== 5) {
            returnError('Invalid token format.', 400);
        }
        
        $stmt = $db->prepare("SELECT * FROM devices WHERE token = ?");
        $stmt->execute([$token]);
        $device = $stmt->fetch();
        
        if (!$device) {
            returnError('Device token not registered.', 404);
        }
        
        if ($device['user_id'] === null) {
            returnError('Device not activated or linked to a user.', 400);
        }
        
        // Find active recording row in 'finishing' or 'recording' state
        $stmtRec = $db->prepare("SELECT id, transcript FROM recordings WHERE user_id = ? AND device_token = ? AND status IN ('recording', 'finishing') ORDER BY id DESC LIMIT 1");
        $stmtRec->execute([$device['user_id'], $token]);
        $recording = $stmtRec->fetch();
        
        if ($recording) {
            $db->beginTransaction();
            try {
                // Update status to completed and record end_time
                $endTime = date('Y-m-d H:i:s');
                $stmtUpdateRec = $db->prepare("UPDATE recordings SET status = 'completed', end_time = ? WHERE id = ?");
                $stmtUpdateRec->execute([$endTime, $recording['id']]);
                
                // Reset device recording state
                $stmtUpdateDev = $db->prepare("UPDATE devices SET recording_state = 0 WHERE id = ?");
                $stmtUpdateDev->execute([$device['id']]);
                
                // Invalidate Redis active recording cache
                Cache::delete('active_transcript_' . $device['user_id']);
                Cache::delete('active_rec_meta_' . $device['user_id']);
                
                $db->commit();
            } catch (Exception $e) {
                $db->rollBack();
                returnError('Failed to complete recording: ' . $e->getMessage(), 500);
            }
        }
        
        returnSuccess(['message' => 'Recording marked as completed successfully.']);
        break;

    default:
        returnError('Action not found.');
        break;
}

// ==========================================
// DEEPGRAM AND GROQ LLM API HELPERS
// ==========================================

function callDeepgramSTT($audioData, $apiKey, $language = 'bn') {
    // Nova-3 model, configured to transcribe customized language (bn, en, or multi)
    $url = "https://api.deepgram.com/v1/listen?model=nova-3&smart_format=true&language=" . urlencode($language);
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $audioData);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Token " . $apiKey,
        "Content-Type: audio/wav"
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10); // 10 seconds connection timeout
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);        // 30 seconds execution timeout
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if ($httpCode !== 200) {
        $err = curl_error($ch);
        curl_close($ch);
        throw new Exception("Deepgram transcription failed with code " . $httpCode . ". Error: " . $err . " Response: " . $response, $httpCode);
    }
    
    curl_close($ch);
    $resData = json_decode($response, true);
    return $resData['results']['channels'][0]['alternatives'][0]['transcript'] ?? '';
}

function callGroqLLM($messages, $settings, $db) {
    $apiKey = $settings['groq_api_key'] ?: getenv('GROQ_API_KEY');
    $model = $settings['groq_model'] ?: getenv('GROQ_MODEL') ?: 'openai/gpt-oss-120b';
    $maxTokens = intval($settings['max_response_tokens'] ?: getenv('MAX_RESPONSE_TOKENS') ?: 1024);
    $temperature = isset($settings['temperature']) ? floatval($settings['temperature']) : 0.7;
    
    if (empty($apiKey)) {
        return "Groq API key not configured in settings. Please configure your API key to use AI features.";
    }
    
    $url = "https://api.groq.com/openai/v1/chat/completions";
    $payload = [
        "model" => $model,
        "messages" => $messages,
        "max_tokens" => $maxTokens,
        "temperature" => $temperature
    ];
    
    $headers = [
        "Authorization: Bearer " . $apiKey,
        "Content-Type: application/json"
    ];
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $resData = json_decode($response, true);
    
    // Fallback logic in case the model is invalid/unavailable on Groq
    if ($httpCode !== 200 || isset($resData['error'])) {
        // Try fallback to llama-3.3-70b-versatile or llama3-8b-8192
        $fallbackModel = 'llama-3.3-70b-versatile';
        $payload['model'] = $fallbackModel;
        
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        $resData = json_decode($response, true);
        if ($httpCode !== 200) {
            return "Groq API Error: " . ($resData['error']['message'] ?? 'Unable to connect to AI service.');
        }
    }
    
    // Update token usage in DB
    $promptTokens = $resData['usage']['prompt_tokens'] ?? 0;
    $completionTokens = $resData['usage']['completion_tokens'] ?? 0;
    $totalTokens = $resData['usage']['total_tokens'] ?? ($promptTokens + $completionTokens);
    
    if ($totalTokens > 0) {
        $stmt = $db->prepare("UPDATE user_settings SET tokens_used = tokens_used + ? WHERE user_id = ?");
        $stmt->execute([$totalTokens, $settings['user_id']]);
    }
    
    return $resData['choices'][0]['message']['content'] ?? 'No response returned from AI.';
}

function generateSummary($transcript, $settings, $db) {
    $messages = [
        ["role" => "system", "content" => "You are an AI assistant designed to summarize meeting transcripts in a professional, clean, Claude-like chatbot style. Provide a comprehensive summary including: key topics discussed, important decisions made, and clear actionable bullet points for follow-up. Keep the summary highly professional, beautifully spaced, and structured.\n\nCRITICAL:\n1. Do NOT use markdown tables or table character separators (such as |).\n2. Do NOT use horizontal rules, separator lines, or dashes (such as ---, ----, or ===).\n3. Do NOT use raw markdown formatting symbols like # or * inside your plain text (for bold headings, you may use **). \n4. Make sure all main headings, key sections, and core topics are in bold (using **Heading**).\n5. Use clean spacing, standard paragraphs, and clear bullet points (- item) for lists."],
        ["role" => "user", "content" => "Please summarize the following meeting transcript:\n\n" . $transcript]
    ];
    return callGroqLLM($messages, $settings, $db);
}

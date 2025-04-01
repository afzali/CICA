<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// تنظیمات پایه
$db_file = 'github_deployer.db';
$setup_completed = false;

// قالب‌های HTML
$header = '<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>سیسا - سامانه یکپارچه سازی و استقرار اتومات</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@100;200;300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: \'Vazirmatn\', Tahoma, Arial, sans-serif;
            background-color: #f8f9fa;
        }
        .navbar-brand {
            font-weight: 700;
        }
        .card {
            border-radius: 8px;
            border: none;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            margin-bottom: 1.5rem;
        }
        .card-header {
            border-radius: 8px 8px 0 0 !important;
        }
        .table th {
            font-weight: 600;
        }
        .form-control, .form-select, .form-check-input {
            border-color: #dee2e6;
        }
        .form-control:focus, .form-select:focus, .form-check-input:focus {
            border-color: #86b7fe;
            box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
        }
        #log-search{
            width: 100%;
            font-family: inherit;
        }
        .text-muted {
            color: #6c757d !important;
        }
        .btn.btn-sm.btn-danger{
            margin-right: 10px;
        } 
    </style>
</head>
<body>
';

$navbar = '<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
    <div class="container">
        <a class="navbar-brand" href="?action=home">سیسا</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item">
                    <a class="nav-link" href="?action=home">داشبورد</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?action=repositories">مخازن</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="?action=logs">گزارش‌ها</a>
                </li>
            </ul>
            <ul class="navbar-nav">
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                        <i class="bi bi-person-circle"></i> '.htmlspecialchars($_SESSION['username'] ?? 'کاربر').'
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li><a class="dropdown-item" href="?action=logout"><i class="bi bi-box-arrow-right me-2"></i> خروج</a></li>
                    </ul>
                </li>
            </ul>
        </div>
    </div>
</nav>
';

$footer = '<footer class="mt-5 py-3 bg-dark text-white">
    <div class="container text-center">
        <small>&copy; '.date('Y').' سیستم سیسا</small>
    </div>
</footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
';

// بررسی وجود دیتابیس و ایجاد در صورت نیاز
try {
    $db = new SQLite3($db_file);
    
    // بررسی وجود جدول‌های مورد نیاز
    $result = $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'");
    if (!$result->fetchArray()) {
        // ایجاد جدول‌های مورد نیاز
        $db->exec("
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE settings (
                id INTEGER PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                value TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY,
                message TEXT NOT NULL,
                level TEXT DEFAULT 'info',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE repositories (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                branch TEXT DEFAULT 'main',
                extract_path TEXT DEFAULT './',
                is_private INTEGER DEFAULT 0,
                github_token TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ");
        
        // ذخیره وضعیت راه‌اندازی
        $setup_completed = false;
    } else {
        // بررسی تکمیل راه‌اندازی اولیه
        $stmt = $db->prepare("SELECT value FROM settings WHERE key = 'setup_completed'");
        $result = $stmt->execute();
        if ($row = $result->fetchArray()) {
            $setup_completed = (bool)$row['value'];
        }
    }
} catch (Exception $e) {
    die('خطا در اتصال به دیتابیس: ' . $e->getMessage());
}

// مسیر درخواست و اقدامات
// تغییر مهم: استفاده از مسیر مطلق فایل فعلی برای هدایت
$current_script = basename($_SERVER['SCRIPT_NAME']);
$action = $_GET['action'] ?? 'home';

// بررسی وب‌هوک گیت‌هاب
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SERVER['HTTP_X_GITHUB_EVENT'])) {
    handle_webhook();
    exit;
}

// احراز هویت کاربر
$logged_in = check_login();

// اگر راه‌اندازی اولیه تکمیل نشده و کاربر در صفحه راه‌اندازی نیست، هدایت به صفحه راه‌اندازی
if (!$setup_completed && $action !== 'setup') {
    header("Location: $current_script?action=setup");
    exit;
}

// اگر راه‌اندازی تکمیل شده ولی کاربر وارد نشده و در صفحه لاگین نیست، هدایت به صفحه لاگین
if ($setup_completed && !$logged_in && !in_array($action, ['login'])) {
    header("Location: $current_script?action=login");
    exit;
}

// پردازش عملیات
switch ($action) {
    case 'setup':
        handle_setup();
        break;
    case 'login':
        handle_login();
        break;
    case 'logout':
        handle_logout();
        break;
    case 'add_repository':
        handle_add_repository();
        break;
    case 'deploy':
        handle_deploy();
        break;
    case 'logs':
        show_logs();
        break;
    case 'repositories':
        show_repositories();
        break;
    case 'delete_repository':
        handle_delete_repository();
        break;
    default:
        show_dashboard();
        break;
}

// ----------------------------------------
// توابع پردازش اصلی
// ----------------------------------------

function handle_webhook() {
    global $db;
    
    $webhook_event = $_SERVER['HTTP_X_GITHUB_EVENT'];
    write_log("وب‌هوک دریافت شد: $webhook_event");
    
    if ($webhook_event !== 'push') {
        http_response_code(200);
        write_log("رویداد وب‌هوک غیر از push دریافت شد: $webhook_event");
        echo json_encode(['status' => 'ignored', 'message' => 'رویداد پشتیبانی نشده']);
        return;
    }
    
    // دریافت اطلاعات از وب‌هوک
    $payload = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($payload['repository']['html_url'])) {
        http_response_code(400);
        write_log("داده‌های وب‌هوک ناقص است.");
        echo json_encode(['status' => 'error', 'message' => 'داده‌های وب‌هوک ناقص است']);
        return;
    }
    
    $repo_url = $payload['repository']['html_url'];
    $branch = isset($payload['ref']) ? str_replace('refs/heads/', '', $payload['ref']) : 'main';
    
    // پیدا کردن مخزن متناظر در دیتابیس
    $stmt = $db->prepare("SELECT * FROM repositories WHERE url = :url");
    $stmt->bindValue(':url', $repo_url, SQLITE3_TEXT);
    $result = $stmt->execute();
    
    if ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        // بررسی شاخه
        if ($row['branch'] !== $branch) {
            write_log("شاخه وب‌هوک ($branch) با شاخه تنظیم شده ({$row['branch']}) مطابقت ندارد. وب‌هوک نادیده گرفته شد.");
            echo json_encode(['status' => 'ignored', 'message' => 'شاخه مورد نظر با تنظیمات مطابقت ندارد']);
            return;
        }
        
        // اجرای دیپلوی
        $success = deploy($row['id']);
        
        if ($success) {
            http_response_code(200);
            echo json_encode(['status' => 'success', 'message' => 'استقرار با موفقیت انجام شد']);
        } else {
            http_response_code(500);
            echo json_encode(['status' => 'error', 'message' => 'خطا در استقرار مخزن']);
        }
    } else {
        write_log("مخزن با آدرس $repo_url در دیتابیس یافت نشد. وب‌هوک نادیده گرفته شد.");
        echo json_encode(['status' => 'ignored', 'message' => 'مخزن در سیستم تعریف نشده است']);
    }
}

function handle_setup() {
    global $db, $setup_completed, $header, $footer, $current_script;
    
    $error = '';
    $success = '';
    
    if ($setup_completed) {
        header("Location: $current_script?action=home");
        exit;
    }
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['setup'])) {
        // اعتبارسنجی فرم راه‌اندازی
        $username = trim($_POST['username'] ?? '');
        $password = trim($_POST['password'] ?? '');
        $password_confirm = trim($_POST['password_confirm'] ?? '');
        
        if (empty($username) || empty($password)) {
            $error = 'نام کاربری و رمز عبور الزامی است.';
        } elseif ($password !== $password_confirm) {
            $error = 'رمز عبور و تکرار آن مطابقت ندارند.';
        } elseif (strlen($password) < 8) {
            $error = 'رمز عبور باید حداقل 8 کاراکتر باشد.';
        } else {
            try {
                // ذخیره کاربر ادمین
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
                $stmt->bindValue(':username', $username, SQLITE3_TEXT);
                $stmt->bindValue(':password', $hashed_password, SQLITE3_TEXT);
                $stmt->execute();
                
                // ثبت تکمیل راه‌اندازی
                $db->exec("INSERT INTO settings (key, value) VALUES ('setup_completed', '1')");
                
                write_log("راه‌اندازی سیستم با موفقیت انجام شد. کاربر $username ایجاد شد.", 'info');
                
                $setup_completed = true;
                $success = 'راه‌اندازی با موفقیت انجام شد. اکنون می‌توانید وارد شوید.';
                
                // انتقال به صفحه لاگین
                header("Location: $current_script?action=login&setup_success=1");
                exit;
            } catch (Exception $e) {
                $error = 'خطا در ثبت اطلاعات: ' . $e->getMessage();
                write_log('خطا در ثبت تنظیمات اولیه: ' . $e->getMessage(), 'error');
            }
        }
    }
    
    echo $header;
    ?>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0">راه‌اندازی اولیه سیستم</h3>
                    </div>
                    <div class="card-body">
                        <?php if($error): ?>
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>
                        
                        <?php if($success): ?>
                            <div class="alert alert-success"><?php echo $success; ?></div>
                        <?php endif; ?>
                        
                        <form method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">نام کاربری ادمین</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                                <div class="form-text">این نام کاربری برای ورود به سیستم استفاده خواهد شد.</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="password" class="form-label">رمز عبور</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                                <div class="form-text">رمز عبور باید حداقل 8 کاراکتر باشد.</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="password_confirm" class="form-label">تکرار رمز عبور</label>
                                <input type="password" class="form-control" id="password_confirm" name="password_confirm" required>
                            </div>
                            
                            <div class="d-grid">
                                <button type="submit" name="setup" class="btn btn-primary">ایجاد حساب و تکمیل راه‌اندازی</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <?php
    echo $footer;
}

function handle_login() {
    global $db, $header, $footer, $current_script;
    
    $error = '';
    $setup_success = isset($_GET['setup_success']) && $_GET['setup_success'] == '1';
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        $username = trim($_POST['username'] ?? '');
        $password = trim($_POST['password'] ?? '');
        
        if (empty($username) || empty($password)) {
            $error = 'نام کاربری و رمز عبور الزامی است.';
        } else {
            // بررسی اطلاعات کاربری
            $stmt = $db->prepare("SELECT * FROM users WHERE username = :username");
            $stmt->bindValue(':username', $username, SQLITE3_TEXT);
            $result = $stmt->execute();
            
            if ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                if (password_verify($password, $row['password'])) {
                    // ورود موفق
                    $_SESSION['user_id'] = $row['id'];
                    $_SESSION['username'] = $row['username'];
                    
                    write_log("کاربر $username با موفقیت وارد شد.", 'info');
                    
                    // انتقال به داشبورد
                    header("Location: $current_script?action=home");
                    exit;
                } else {
                    $error = 'رمز عبور نادرست است.';
                    write_log("تلاش ناموفق برای ورود با نام کاربری $username (رمز عبور اشتباه)", 'warning');
                }
            } else {
                $error = 'کاربری با این مشخصات یافت نشد.';
                write_log("تلاش ناموفق برای ورود با نام کاربری $username (کاربر وجود ندارد)", 'warning');
            }
        }
    }
    
    echo $header;
    ?>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-5">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0">ورود به سیستم</h3>
                    </div>
                    <div class="card-body">
                        <?php if($setup_success): ?>
                            <div class="alert alert-success">راه‌اندازی با موفقیت انجام شد. اکنون می‌توانید وارد شوید.</div>
                        <?php endif; ?>
                        
                        <?php if($error): ?>
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>
                        
                        <form method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">نام کاربری</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            
                            <div class="mb-3">
                                <label for="password" class="form-label">رمز عبور</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            
                            <div class="d-grid">
                                <button type="submit" name="login" class="btn btn-primary">ورود</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <?php
    echo $footer;
}

function handle_logout() {
    global $current_script;
    
    // خروج از سیستم
    $_SESSION = array();
    session_destroy();
    
    // انتقال به صفحه لاگین
    header("Location: $current_script?action=login");
    exit;
}

function show_dashboard() {
    global $db, $setup_completed, $header, $navbar, $footer;
    
    // دریافت آمار کلی
    $repo_count = $db->querySingle("SELECT COUNT(*) FROM repositories");
    $log_count = $db->querySingle("SELECT COUNT(*) FROM logs");
    $last_deploy = $db->querySingle("SELECT MAX(created_at) FROM logs WHERE message LIKE '%با موفقیت مستقر شد%'");
    
    // دریافت آخرین لاگ‌ها
    $logs = [];
    $result = $db->query("SELECT * FROM logs ORDER BY created_at DESC LIMIT 5");
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $logs[] = $row;
    }
    
    // دریافت مخازن
    $repos = [];
    $result = $db->query("SELECT * FROM repositories ORDER BY created_at DESC");
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $repos[] = $row;
    }
    
    echo $header;
    echo $navbar;
    ?>
    <div class="container mt-4">
        <h2 class="mb-4">داشبورد</h2>
        
        <div class="row mb-4">
            <div class="col-md-4 mb-3">
                <div class="card bg-primary text-white h-100">
                    <div class="card-body">
                        <h5 class="card-title">تعداد مخازن</h5>
                        <p class="card-text display-4"><?php echo $repo_count; ?></p>
                    </div>
                    <div class="card-footer d-flex">
                        <a href="?action=repositories" class="text-white text-decoration-none">
                            مدیریت مخازن <i class="bi bi-arrow-right-circle ms-2"></i>
                        </a>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4 mb-3">
                <div class="card bg-info text-white h-100">
                    <div class="card-body">
                        <h5 class="card-title">تعداد گزارش‌ها</h5>
                        <p class="card-text display-4"><?php echo $log_count; ?></p>
                    </div>
                    <div class="card-footer d-flex">
                        <a href="?action=logs" class="text-white text-decoration-none">
                            مشاهده گزارش‌ها <i class="bi bi-arrow-right-circle ms-2"></i>
                        </a>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4 mb-3">
                <div class="card bg-success text-white h-100">
                    <div class="card-body">
                        <h5 class="card-title">آخرین استقرار</h5>
                        <p class="card-text"><?php echo $last_deploy ? date('Y-m-d H:i:s', strtotime($last_deploy)) : 'تاکنون استقراری انجام نشده'; ?></p>
                    </div>
                    <div class="card-footer">
                        <span class="text-white">
                            <?php echo $last_deploy ? 'در ' . human_time_diff($last_deploy) . ' پیش' : ''; ?>
                        </span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-8 mb-4">
                <div class="card shadow-sm">
                    <div class="card-header d-flex justify-content-between">
                        <h5 class="mb-0">مخازن تعریف‌شده</h5>
                        <a href="?action=add_repository" class="btn btn-sm btn-primary">افزودن مخزن جدید</a>
                    </div>
                    
                    <?php if(count($repos) > 0): ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th>نام</th>
                                        <th>شاخه</th>
                                        <th>نوع</th>
                                        <th>عملیات</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach($repos as $repo): ?>
                                        <tr>
                                            <td>
                                                <?php echo htmlspecialchars($repo['name']); ?>
                                                <small class="d-block text-muted"><?php echo htmlspecialchars($repo['url']); ?></small>
                                            </td>
                                            <td><?php echo htmlspecialchars($repo['branch']); ?></td>
                                            <td>
                                                <?php if($repo['is_private']): ?>
                                                    <span class="badge bg-danger">خصوصی</span>
                                                <?php else: ?>
                                                    <span class="badge bg-success">عمومی</span>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <a href="?action=deploy&id=<?php echo $repo['id']; ?>" class="btn btn-sm btn-success">استقرار</a>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php else: ?>
                        <div class="card-body">
                            <div class="alert alert-info mb-0">مخزنی تعریف نشده است. برای شروع یک مخزن جدید اضافه کنید.</div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <div class="col-md-4 mb-4">
                <div class="card shadow-sm">
                    <div class="card-header d-flex justify-content-between">
                        <h5 class="mb-0">آخرین گزارش‌ها</h5>
                        <a href="?action=logs" class="text-decoration-none">همه گزارش‌ها</a>
                    </div>
                    
                    <?php if(count($logs) > 0): ?>
                        <ul class="list-group list-group-flush">
                            <?php foreach($logs as $log): ?>
                                <li class="list-group-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <?php
                                            $badge_class = 'bg-info';
                                            if ($log['level'] === 'error') $badge_class = 'bg-danger';
                                            elseif ($log['level'] === 'warning') $badge_class = 'bg-warning';
                                            elseif ($log['level'] === 'success') $badge_class = 'bg-success';
                                            ?>
                                            <span class="badge <?php echo $badge_class; ?> me-2"><?php echo $log['level']; ?></span>
                                            <?php echo htmlspecialchars($log['message']); ?>
                                        </div>
                                        <small class="text-muted"><?php echo human_time_diff($log['created_at']); ?></small>
                                    </div>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php else: ?>
                        <div class="card-body">
                            <div class="alert alert-info mb-0">هیچ گزارشی ثبت نشده است.</div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    <?php
    echo $footer;
}

// بقیه توابع مانند قبل، فقط به جای include به متغیرهای $header, $navbar, $footer اشاره می‌کنند...
// ادامه کد، توابع بعدی را به همین شکل تغییر دهید
// ...

// تابع handle_add_repository
function handle_add_repository() {
    global $db, $header, $navbar, $footer, $current_script;
    
    $error = '';
    $success = '';
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_repository'])) {
        // اعتبارسنجی فرم افزودن مخزن
        $name = trim($_POST['name'] ?? '');
        $url = trim($_POST['url'] ?? '');
        $branch = trim($_POST['branch'] ?? 'main');
        $extract_path = trim($_POST['extract_path'] ?? './');
        $is_private = isset($_POST['is_private']) ? 1 : 0;
        $github_token = $is_private ? trim($_POST['github_token'] ?? '') : '';
        
        if (empty($name) || empty($url)) {
            $error = 'نام و آدرس مخزن الزامی است.';
        } elseif ($is_private && empty($github_token)) {
            $error = 'برای مخازن خصوصی، وارد کردن توکن گیت‌هاب الزامی است.';
        } else {
            try {
                // ذخیره مخزن جدید
                $stmt = $db->prepare("
                    INSERT INTO repositories (name, url, branch, extract_path, is_private, github_token)
                    VALUES (:name, :url, :branch, :extract_path, :is_private, :github_token)
                ");
                
                $stmt->bindValue(':name', $name, SQLITE3_TEXT);
                $stmt->bindValue(':url', $url, SQLITE3_TEXT);
                $stmt->bindValue(':branch', $branch, SQLITE3_TEXT);
                $stmt->bindValue(':extract_path', $extract_path, SQLITE3_TEXT);
                $stmt->bindValue(':is_private', $is_private, SQLITE3_INTEGER);
                $stmt->bindValue(':github_token', $github_token, SQLITE3_TEXT);
                
                $stmt->execute();
                
                write_log("مخزن جدید «{$name}» با آدرس {$url} اضافه شد.", 'success');
                
                $success = 'مخزن جدید با موفقیت اضافه شد.';
                
                // انتقال به صفحه مدیریت مخازن
                header("Location: $current_script?action=repositories&added=1");
                exit;
            } catch (Exception $e) {
                $error = 'خطا در ثبت مخزن: ' . $e->getMessage();
                write_log('خطا در افزودن مخزن جدید: ' . $e->getMessage(), 'error');
            }
        }
    }
    
    echo $header;
    echo $navbar;
    ?>
    <div class="container mt-4">
        <div class="row">
            <div class="col-md-8 offset-md-2">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0">افزودن مخزن جدید</h3>
                    </div>
                    <div class="card-body">
                        <?php if($error): ?>
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>
                        
                        <?php if($success): ?>
                            <div class="alert alert-success"><?php echo $success; ?></div>
                        <?php endif; ?>
                        
                        <form method="post">
                            <div class="mb-3">
                                <label for="name" class="form-label">نام مخزن</label>
                                <input type="text" class="form-control" id="name" name="name" required>
                                <div class="form-text">یک نام دلخواه برای شناسایی مخزن</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="url" class="form-label">آدرس مخزن</label>
                                <input type="url" class="form-control" id="url" name="url" 
                                       placeholder="https://github.com/username/repository" required>
                                <div class="form-text">آدرس HTTP یا HTTPS مخزن گیت‌هاب (بدون .git در انتها)</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="branch" class="form-label">شاخه</label>
                                <input type="text" class="form-control" id="branch" name="branch" value="main">
                                <div class="form-text">شاخه‌ای که می‌خواهید از آن استقرار انجام شود (معمولاً main یا master)</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="extract_path" class="form-label">مسیر استقرار</label>
                                <input type="text" class="form-control" id="extract_path" name="extract_path" value="./">
                                <div class="form-text">مسیر نسبی یا مطلقی که فایل‌ها در آن مستقر شوند (به صورت پیش‌فرض پوشه فعلی)</div>
                            </div>
                            
                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="is_private" name="is_private" onchange="toggleTokenField()">
                                <label class="form-check-label" for="is_private">این مخزن خصوصی است</label>
                            </div>
                            
                            <div id="token_section" class="mb-3" style="display: none;">
                                <label for="github_token" class="form-label">توکن دسترسی گیت‌هاب</label>
                                <input type="password" class="form-control" id="github_token" name="github_token">
                                <div class="form-text">
                                    توکن دسترسی شخصی گیت‌هاب برای دسترسی به مخزن خصوصی. 
                                    <a href="https://github.com/settings/tokens" target="_blank">ساخت توکن جدید</a>
                                </div>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                <a href="?action=repositories" class="btn btn-secondary me-md-2">انصراف</a>
                                <button type="submit" name="add_repository" class="btn btn-primary">ثبت مخزن</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function toggleTokenField() {
            const isPrivate = document.getElementById('is_private').checked;
            document.getElementById('token_section').style.display = isPrivate ? 'block' : 'none';
            if (isPrivate) {
                document.getElementById('github_token').setAttribute('required', 'required');
            } else {
                document.getElementById('github_token').removeAttribute('required');
            }
        }
    </script>
    <?php
    echo $footer;
}

// تابع show_repositories
function show_repositories() {
    global $db, $header, $navbar, $footer;
    
    $success = isset($_GET['added']) ? 'مخزن جدید با موفقیت اضافه شد.' : '';
    $deleted = isset($_GET['deleted']) ? 'مخزن با موفقیت حذف شد.' : '';
    
    // دریافت همه مخازن
    $repos = [];
    $result = $db->query("SELECT * FROM repositories ORDER BY name ASC");
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $repos[] = $row;
    }
    
    echo $header;
    echo $navbar;
    ?>
    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>مدیریت مخازن</h2>
            <a href="?action=add_repository" class="btn btn-primary">
                <i class="bi bi-plus-lg"></i> افزودن مخزن جدید
            </a>
        </div>
        
        <?php if($success): ?>
            <div class="alert alert-success"><?php echo $success; ?></div>
        <?php endif; ?>
        
        <?php if($deleted): ?>
            <div class="alert alert-success"><?php echo $deleted; ?></div>
        <?php endif; ?>
        
        <?php if(count($repos) > 0): ?>
            <div class="card shadow">
                <div class="table-responsive">
                    <table class="table table-striped table-hover mb-0">
                        <thead>
                            <tr>
                                <th>نام</th>
                                <th>آدرس</th>
                                <th>شاخه</th>
                                <th>مسیر استقرار</th>
                                <th>نوع</th>
                                <th>آخرین بروزرسانی</th>
                                <th>عملیات</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach($repos as $repo): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($repo['name']); ?></td>
                                    <td>
                                        <small>
                                            <a href="<?php echo htmlspecialchars($repo['url']); ?>" target="_blank">
                                                <?php echo htmlspecialchars($repo['url']); ?>
                                            </a>
                                        </small>
                                    </td>
                                    <td><?php echo htmlspecialchars($repo['branch']); ?></td>
                                    <td><small><?php echo htmlspecialchars($repo['extract_path']); ?></small></td>
                                    <td>
                                        <?php if($repo['is_private']): ?>
                                            <span class="badge bg-danger">خصوصی</span>
                                        <?php else: ?>
                                            <span class="badge bg-success">عمومی</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <small><?php echo date('Y-m-d H:i', strtotime($repo['updated_at'])); ?></small>
                                    </td>
                                    <td>
                                        <div class="btn-group" role="group">
                                            <a href="?action=deploy&id=<?php echo $repo['id']; ?>" class="btn btn-sm btn-success">استقرار</a>
                                            <button type="button" class="btn btn-sm btn-danger" 
                                                    onclick="confirmDelete(<?php echo $repo['id']; ?>, '<?php echo htmlspecialchars($repo['name']); ?>')">
                                                حذف
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php else: ?>
            <div class="alert alert-info">
                هیچ مخزنی تعریف نشده است. برای شروع روی دکمه "افزودن مخزن جدید" کلیک کنید.
            </div>
        <?php endif; ?>
    </div>
    
    <!-- Modal تأیید حذف -->
    <div class="modal fade" id="deleteModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">تأیید حذف</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>آیا از حذف مخزن <strong id="repoName"></strong> اطمینان دارید؟ این عملیات قابل بازگشت نیست.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">انصراف</button>
                    <a href="#" id="deleteLink" class="btn btn-danger">حذف</a>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function confirmDelete(id, name) {
            document.getElementById('repoName').textContent = name;
            document.getElementById('deleteLink').href = '?action=delete_repository&id=' + id;
            
            var deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
            deleteModal.show();
        }
    </script>
    <?php
    echo $footer;
}

function handle_delete_repository() {
    global $db, $current_script;
    
    if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
        header("Location: $current_script?action=repositories");
        exit;
    }
    
    $id = (int)$_GET['id'];
    
    // بررسی وجود مخزن
    $stmt = $db->prepare("SELECT name FROM repositories WHERE id = :id");
    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    if ($row = $result->fetchArray()) {
        $name = $row['name'];
        
        // حذف مخزن
        $stmt = $db->prepare("DELETE FROM repositories WHERE id = :id");
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->execute();
        
        write_log("مخزن «{$name}» حذف شد.", 'warning');
        
        header("Location: $current_script?action=repositories&deleted=1");
    } else {
        header("Location: $current_script?action=repositories");
    }
    
    exit;
}

function handle_deploy() {
    global $db, $current_script;
    
    if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
        header("Location: $current_script?action=repositories");
        exit;
    }
    
    $id = (int)$_GET['id'];
    $success = deploy($id);
    
    if ($success) {
        header("Location: $current_script?action=repositories&deployed=1");
    } else {
        header("Location: $current_script?action=repositories&deploy_failed=1");
    }
    
    exit;
}

function deploy($repo_id) {
    global $db;
    
    // دریافت اطلاعات مخزن
    $stmt = $db->prepare("SELECT * FROM repositories WHERE id = :id");
    $stmt->bindValue(':id', $repo_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    if (!($repo = $result->fetchArray(SQLITE3_ASSOC))) {
        write_log("خطا در استقرار: مخزن با شناسه $repo_id یافت نشد.", 'error');
        return false;
    }
    
    write_log("شروع استقرار مخزن «{$repo['name']}» با شاخه {$repo['branch']}...");
    
    // ساخت URL دانلود ZIP
    $zip_url = str_replace(".git", "", $repo['url']);
    $zip_url = rtrim($zip_url, "/") . "/archive/refs/heads/{$repo['branch']}.zip";
    
    // ایجاد نام فایل موقت ZIP
    $temp_zip = tempnam(sys_get_temp_dir(), "github_");
    
    // دانلود فایل ZIP
    write_log("در حال دانلود از: $zip_url");
    
    $zip_content = download_file($zip_url, $repo['is_private'] ? $repo['github_token'] : null);
    
    if (!$zip_content) {
        write_log("خطا: دانلود فایل ZIP ناموفق بود", 'error');
        return false;
    }
    
    // ذخیره فایل ZIP
    file_put_contents($temp_zip, $zip_content);
    $zip_size = round(strlen($zip_content)/1024/1024, 2);
    write_log("فایل ZIP دانلود شد: $temp_zip ($zip_size MB)");
    
    // استخراج ZIP
    $zip = new ZipArchive;
    $res = $zip->open($temp_zip);
    
    if ($res === TRUE) {
        // تعیین نام پوشه اصلی داخل ZIP
        $folder_name = $zip->getNameIndex(0);
        
        // استخراج همه فایل‌ها
        $zip->extractTo(sys_get_temp_dir());
        $zip->close();
        
        write_log("فایل ZIP با موفقیت استخراج شد");
        
        // کپی فایل‌ها از پوشه استخراج شده به مسیر مقصد
        $src_path = sys_get_temp_dir() . '/' . $folder_name;
        $extract_path = $repo['extract_path'];
        
        // مطمئن شویم مسیر مقصد وجود دارد
        if (!is_dir($extract_path)) {
            mkdir($extract_path, 0755, true);
            write_log("پوشه مقصد $extract_path ساخته شد");
        }
        
        write_log("در حال کپی فایل‌ها از $src_path به $extract_path");
        copy_directory($src_path, $extract_path);
        
        // پاک کردن فایل‌های موقت
        unlink($temp_zip);
        delete_directory(sys_get_temp_dir() . '/' . rtrim($folder_name, '/'));
        
        // بروزرسانی زمان آخرین استقرار
        $stmt = $db->prepare("UPDATE repositories SET updated_at = CURRENT_TIMESTAMP WHERE id = :id");
        $stmt->bindValue(':id', $repo_id, SQLITE3_INTEGER);
        $stmt->execute();
        
        write_log("مخزن «{$repo['name']}» با موفقیت مستقر شد", 'success');
        return true;
    } else {
        write_log("خطا: استخراج ZIP ناموفق بود (کد خطا: $res)", 'error');
        unlink($temp_zip);
        return false;
    }
}

function show_logs() {
    global $db, $header, $navbar, $footer;
    
    // پارامترهای فیلتر و صفحه‌بندی
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $level = isset($_GET['level']) ? $_GET['level'] : '';
    $search = isset($_GET['search']) ? $_GET['search'] : '';
    
    $per_page = 20;
    $offset = ($page - 1) * $per_page;
    
    // ساخت کوئری جستجو
    $query = "SELECT * FROM logs";
    $count_query = "SELECT COUNT(*) FROM logs";
    $params = [];
    
    $wheres = [];
    if (!empty($level)) {
        $wheres[] = "level = :level";
        $params[':level'] = $level;
    }
    
    if (!empty($search)) {
        $wheres[] = "message LIKE :search";
        $params[':search'] = "%$search%";
    }
    
    if (!empty($wheres)) {
        $query .= " WHERE " . implode(" AND ", $wheres);
        $count_query .= " WHERE " . implode(" AND ", $wheres);
    }
    
    $query .= " ORDER BY created_at DESC LIMIT :limit OFFSET :offset";
    $params[':limit'] = $per_page;
    $params[':offset'] = $offset;
    
    // اجرای کوئری شمارش
    $stmt = $db->prepare($count_query);
    foreach ($params as $key => $value) {
        if ($key !== ':limit' && $key !== ':offset') {
            $stmt->bindValue($key, $value);
        }
    }
    $total_rows = $stmt->execute()->fetchArray()[0];
    $total_pages = ceil($total_rows / $per_page);
    
    // اجرای کوئری اصلی
    $stmt = $db->prepare($query);
    foreach ($params as $key => $value) {
        if ($key === ':limit') {
            $stmt->bindValue($key, $value, SQLITE3_INTEGER);
        } elseif ($key === ':offset') {
            $stmt->bindValue($key, $value, SQLITE3_INTEGER);
        } else {
            $stmt->bindValue($key, $value);
        }
    }
    
    $result = $stmt->execute();
    $logs = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $logs[] = $row;
    }
    
    echo $header;
    echo $navbar;
    ?>
    <div class="container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>گزارش‌ها</h2>
            <div>
                <?php if(!empty($search) || !empty($level)): ?>
                    <a href="?action=logs" class="btn btn-outline-secondary me-2">حذف فیلترها</a>
                <?php endif; ?>
            </div>
        </div>
        
        <div class="card shadow mb-4">
            <div class="card-header bg-white">
                <form method="get" class="row g-3">
                    <input type="hidden" name="action" value="logs">
                    
                    <div class="col-md-6">
                        <div class="input-group">
                            <input type="text" class="form-control" id="log-search" name="search" placeholder="جستجو در گزارش‌ها..." 
                                   value="<?php echo htmlspecialchars($search); ?>">
                            <button class="btn btn-primary" type="submit">جستجو</button>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <select name="level" class="form-select" onchange="this.form.submit()">
                            <option value="">همه سطوح</option>
                            <option value="info" <?php echo $level === 'info' ? 'selected' : ''; ?>>اطلاعات</option>
                            <option value="success" <?php echo $level === 'success' ? 'selected' : ''; ?>>موفقیت</option>
                            <option value="warning" <?php echo $level === 'warning' ? 'selected' : ''; ?>>هشدار</option>
                            <option value="error" <?php echo $level === 'error' ? 'selected' : ''; ?>>خطا</option>
                        </select>
                    </div>
                </form>
            </div>
            
            <?php if(count($logs) > 0): ?>
                <div class="table-responsive">
                    <table class="table table-striped mb-0">
                        <thead>
                            <tr>
                                <th>تاریخ</th>
                                <th>سطح</th>
                                <th>پیام</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach($logs as $log): ?>
                                <tr>
                                    <td nowrap><?php echo date('Y-m-d H:i:s', strtotime($log['created_at'])); ?></td>
                                    <td>
                                        <?php
                                        $badge_class = 'bg-info';
                                        if ($log['level'] === 'error') $badge_class = 'bg-danger';
                                        elseif ($log['level'] === 'warning') $badge_class = 'bg-warning';
                                        elseif ($log['level'] === 'success') $badge_class = 'bg-success';
                                        ?>
                                        <span class="badge <?php echo $badge_class; ?>"><?php echo $log['level']; ?></span>
                                    </td>
                                    <td><?php echo htmlspecialchars($log['message']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                
                <?php if($total_pages > 1): ?>
                    <div class="card-footer bg-white">
                        <nav>
                            <ul class="pagination justify-content-center mb-0">
                                <?php if($page > 1): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?action=logs&page=<?php echo $page-1; ?><?php echo !empty($level) ? '&level='.urlencode($level) : ''; ?><?php echo !empty($search) ? '&search='.urlencode($search) : ''; ?>">
                                            قبلی
                                        </a>
                                    </li>
                                <?php else: ?>
                                    <li class="page-item disabled"><span class="page-link">قبلی</span></li>
                                <?php endif; ?>
                                
                                <?php for($i = max(1, $page-2); $i <= min($total_pages, $page+2); $i++): ?>
                                    <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                                        <a class="page-link" href="?action=logs&page=<?php echo $i; ?><?php echo !empty($level) ? '&level='.urlencode($level) : ''; ?><?php echo !empty($search) ? '&search='.urlencode($search) : ''; ?>">
                                            <?php echo $i; ?>
                                        </a>
                                    </li>
                                <?php endfor; ?>
                                
                                <?php if($page < $total_pages): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?action=logs&page=<?php echo $page+1; ?><?php echo !empty($level) ? '&level='.urlencode($level) : ''; ?><?php echo !empty($search) ? '&search='.urlencode($search) : ''; ?>">
                                            بعدی
                                        </a>
                                    </li>
                                <?php else: ?>
                                    <li class="page-item disabled"><span class="page-link">بعدی</span></li>
                                <?php endif; ?>
                            </ul>
                        </nav>
                    </div>
                <?php endif; ?>
            <?php else: ?>
                <div class="card-body">
                    <div class="alert alert-info mb-0">هیچ گزارشی یافت نشد.</div>
                </div>
            <?php endif; ?>
        </div>
    </div>
    <?php
    echo $footer;
}

// ----------------------------------------
// توابع کمکی
// ----------------------------------------

function check_login() {
    return isset($_SESSION['user_id']) && $_SESSION['user_id'] > 0;
}

function download_file($url, $token = null) {
    $context_options = [
        'http' => [
            'method' => 'GET',
            'header' => [
                'User-Agent: PHP GitHub Deployer',
            ],
            'timeout' => 60,
        ],
    ];
    
    // اگر توکن وجود داشت، آن را به هدر اضافه کن
    if (!empty($token)) {
        $context_options['http']['header'][] = 'Authorization: token ' . $token;
    }
    
    $context = stream_context_create($context_options);
    
    try {
        $content = file_get_contents($url, false, $context);
        
        // بررسی خطا
        if ($content === false) {
            $error = error_get_last();
            write_log("خطا در دانلود: " . ($error['message'] ?? 'خطای نامشخص'), 'error');
            return false;
        }
        
        // بررسی حجم دانلود
        if (empty($content) || strlen($content) < 1000) { // کمتر از 1KB احتمالاً خطاست
            write_log("فایل دانلود شده خیلی کوچک است. احتمال خطا در دانلود یا دسترسی.", 'error');
            return false;
        }
        
        return $content;
    } catch (Exception $e) {
        write_log("خطا در دانلود: " . $e->getMessage(), 'error');
        return false;
    }
}

function copy_directory($src, $dst) {
    // ساخت پوشه مقصد اگر وجود ندارد
    if (!is_dir($dst)) {
        mkdir($dst, 0755, true);
    }
    
    try {
        $files = new DirectoryIterator($src);
        foreach ($files as $file) {
            if ($file->isDot()) continue;
            
            $srcPath = $src . '/' . $file->getFilename();
            $dstPath = $dst . '/' . $file->getFilename();
            
            if ($file->isDir()) {
                copy_directory($srcPath, $dstPath);
            } else {
                if (!copy($srcPath, $dstPath)) {
                    write_log("خطا در کپی فایل: $srcPath به $dstPath", 'error');
                }
            }
        }
    } catch (Exception $e) {
        write_log("خطا در کپی پوشه: " . $e->getMessage(), 'error');
        return false;
    }
    
    return true;
}

function delete_directory($dir) {
    if (!is_dir($dir)) {
        return;
    }
    
    try {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        
        foreach ($files as $file) {
            if ($file->isDir()) {
                rmdir($file->getRealPath());
            } else {
                unlink($file->getRealPath());
            }
        }
        
        rmdir($dir);
    } catch (Exception $e) {
        write_log("خطا در حذف پوشه: " . $e->getMessage(), 'error');
        return false;
    }
    
    return true;
}

function write_log($message, $level = 'info') {
    global $db;
    
    $stmt = $db->prepare("INSERT INTO logs (message, level) VALUES (:message, :level)");
    $stmt->bindValue(':message', $message, SQLITE3_TEXT);
    $stmt->bindValue(':level', $level, SQLITE3_TEXT);
    $stmt->execute();
}

function human_time_diff($datetime) {
    $now = new DateTime();
    $past = new DateTime($datetime);
    $diff = $now->diff($past);
    
    if($diff->y > 0) {
        return $diff->y . ' سال پیش';
    }
    elseif($diff->m > 0) {
        return $diff->m . ' ماه پیش';
    }
    elseif($diff->d > 0) {
        return $diff->d . ' روز پیش';
    }
    elseif($diff->h > 0) {
        return $diff->h . ' ساعت پیش';
    }
    elseif($diff->i > 0) {
        return $diff->i . ' دقیقه پیش';
    }
    else {
        return 'چند لحظه پیش';
    }
}
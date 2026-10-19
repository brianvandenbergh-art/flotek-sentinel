<?php
/**
 * Plugin Name: Flotek Sentinel Agent
 * Description: Must-use agent for Flotek Sentinel. Drop this file in wp-content/mu-plugins/.
 * Version: 1.0.0
 *
 * Paste the hub secret from Sentinel → Settings into FLOTEK_SENTINEL_SECRET.
 * The secret is compared with hash_equals. Do not commit a filled-in copy to a public repository.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('FLOTEK_SENTINEL_SECRET')) {
    define('FLOTEK_SENTINEL_SECRET', 'REPLACE_WITH_SECRET_FROM_SENTINEL_SETTINGS');
}

add_action('init', function () {
    $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
    if (strpos($uri, 'flotek/v1') === false) {
        return;
    }
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Headers: X-Hub-Secret, Content-Type, X-Flotek-Disable');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        status_header(204);
        exit;
    }
}, 0);

/**
 * A faulty plugin can fatal before REST runs. This filter runs first and can
 * skip that plugin for the current request when Sentinel sends X-Flotek-Disable.
 */
add_filter('option_active_plugins', function ($plugins) {
    if (!is_array($plugins)) {
        $plugins = array();
    }
    $forced = get_option('flotek_force_disabled', array());
    if (is_array($forced) && $forced) {
        $plugins = array_values(array_diff($plugins, $forced));
    }
    $header = isset($_SERVER['HTTP_X_FLOTEK_DISABLE']) ? (string) $_SERVER['HTTP_X_FLOTEK_DISABLE'] : '';
    $secret = isset($_SERVER['HTTP_X_HUB_SECRET']) ? (string) $_SERVER['HTTP_X_HUB_SECRET'] : '';
    if ($header !== '' && hash_equals(FLOTEK_SENTINEL_SECRET, $secret)) {
        if ($header === '*') {
            return array();
        }
        $plugins = array_values(array_filter($plugins, function ($plugin) use ($header) {
            return $plugin !== $header && basename($plugin) !== $header;
        }));
    }
    return $plugins;
}, 1);

add_action('rest_api_init', function () {
    $routes = array(
        array('health', 'GET', 'flotek_sentinel_health'),
        array('visits', 'GET', 'flotek_sentinel_visit_report'),
        array('create-user', 'POST', 'flotek_sentinel_create_user'),
        array('reset-password', 'POST', 'flotek_sentinel_reset_password'),
        array('delete-user', 'POST', 'flotek_sentinel_delete_user'),
        array('update-plugins', 'POST', 'flotek_sentinel_update_plugins'),
        array('update-plugin', 'POST', 'flotek_sentinel_update_one'),
        array('create-backup', 'POST', 'flotek_sentinel_create_backup'),
        array('rollback', 'POST', 'flotek_sentinel_rollback'),
        array('restore-backup', 'POST', 'flotek_sentinel_restore_backup'),
        array('upload-backup', 'POST', 'flotek_sentinel_upload_backup'),
        array('disable-plugin', 'POST', 'flotek_sentinel_disable_plugin'),
        array('update-settings', 'POST', 'flotek_sentinel_update_settings'),
        array('security', 'GET', 'flotek_sentinel_security'),
        array('update-policy', 'POST', 'flotek_sentinel_update_policy'),
        array('update-core', 'POST', 'flotek_sentinel_update_core'),
        array('update-themes', 'POST', 'flotek_sentinel_update_themes'),
        array('block-ip', 'POST', 'flotek_sentinel_block_ip'),
        array('allow-ip', 'POST', 'flotek_sentinel_allow_ip'),
        array('accept-files', 'POST', 'flotek_sentinel_accept_files'),
        array('seo', 'GET', 'flotek_sentinel_seo'),
        array('relay', 'GET', 'flotek_sentinel_relay'),
        array('journey', 'GET', 'flotek_sentinel_journey'),
        array('backup-settings', 'POST', 'flotek_sentinel_backup_settings'),
        array('create-full-backup', 'POST', 'flotek_sentinel_full_backup'),
    );
    foreach ($routes as $route) {
        register_rest_route('flotek/v1', '/' . $route[0], array(
            'methods' => $route[1],
            'callback' => $route[2],
            'permission_callback' => 'flotek_sentinel_authorized',
        ));
    }
});

function flotek_sentinel_authorized($request) {
    $given = (string) $request->get_header('x-hub-secret');
    if ($given === '' || !hash_equals(FLOTEK_SENTINEL_SECRET, $given)) {
        return new WP_Error('forbidden', 'Unauthorized hub secret', array('status' => 403));
    }
    return true;
}

function flotek_sentinel_health() {
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $theme = wp_get_theme();
    $plugins = array();
    $updates = get_site_transient('update_plugins');
    foreach (get_plugins() as $file => $plugin) {
        $new_version = '';
        if (is_object($updates) && isset($updates->response[$file])) {
            $new_version = $updates->response[$file]->new_version ?? '';
        }
        $plugins[] = array(
            'file' => $file,
            'name' => $plugin['Name'],
            'version' => $plugin['Version'],
            'active' => is_plugin_active($file),
            'has_update' => $new_version !== '',
            'new_version' => $new_version,
        );
    }
    $users = array();
    foreach (get_users(array('number' => 100, 'fields' => 'all')) as $user) {
        $users[] = array(
            'id' => $user->ID,
            'user_login' => $user->user_login,
            'user_email' => $user->user_email,
            'roles' => $user->roles,
        );
    }
    $backups = array();
    $dir = WP_CONTENT_DIR . '/flotek-backups';
    if (is_dir($dir)) {
        foreach (scandir($dir) as $file) {
            if (!preg_match('/\.(sql|zip)$/i', $file)) {
                continue;
            }
            $path = $dir . '/' . $file;
            $backups[] = array(
                'filename' => $file,
                'filesize' => size_format(filesize($path)),
                'location' => $path,
            );
        }
    }
    return array(
        'success' => true,
        'site_name' => get_bloginfo('name'),
        'tagline' => get_bloginfo('description'),
        'site_url' => home_url(),
        'wp_version' => get_bloginfo('version'),
        'php_version' => PHP_VERSION,
        'theme' => array('name' => $theme->get('Name'), 'version' => $theme->get('Version')),
        'plugins' => $plugins,
        'users' => $users,
        'backups' => $backups,
        'visits' => flotek_sentinel_visit_report(),
        'performance' => array(
            'memory' => size_format(memory_get_usage(true)),
        ),
    );
}

function flotek_sentinel_create_user($request) {
    $username = sanitize_user((string) $request->get_param('username'));
    $email = sanitize_email((string) $request->get_param('email'));
    $role = sanitize_key((string) $request->get_param('role'));
    $password = (string) $request->get_param('password');
    $allowed = array('administrator', 'editor', 'author', 'contributor', 'subscriber');
    if (!$username || !$email || !$password || !in_array($role, $allowed, true)) {
        return new WP_Error('bad_request', 'Username, email, role and password are required', array('status' => 400));
    }
    $id = wp_insert_user(array(
        'user_login' => $username,
        'user_email' => $email,
        'user_pass' => $password,
        'role' => $role,
    ));
    if (is_wp_error($id)) {
        return new WP_Error('failed', $id->get_error_message(), array('status' => 400));
    }
    return array('success' => true, 'id' => $id);
}

function flotek_sentinel_reset_password($request) {
    $user_id = (int) $request->get_param('user_id');
    $password = (string) $request->get_param('new_password');
    if ($user_id < 1 || $password === '' || !get_user_by('id', $user_id)) {
        return new WP_Error('bad_request', 'A valid user and password are required', array('status' => 400));
    }
    wp_set_password($password, $user_id);
    return array('success' => true);
}

function flotek_sentinel_delete_user($request) {
    $user_id = (int) $request->get_param('user_id');
    if ($user_id < 1 || $user_id === get_current_user_id()) {
        return new WP_Error('bad_request', 'That user cannot be deleted', array('status' => 400));
    }
    require_once ABSPATH . 'wp-admin/includes/user.php';
    if (!wp_delete_user($user_id)) {
        return new WP_Error('failed', 'WordPress did not delete that user', array('status' => 400));
    }
    return array('success' => true);
}

function flotek_sentinel_update_plugins() {
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
    require_once ABSPATH . 'wp-admin/includes/update.php';
    wp_update_plugins();
    $updates = get_site_transient('update_plugins');
    $files = array();
    if (is_object($updates) && !empty($updates->response)) {
        $files = array_keys($updates->response);
    }
    if (!$files) {
        return array('success' => true, 'updated' => array());
    }
    $skin = new Automatic_Upgrader_Skin();
    $upgrader = new Plugin_Upgrader($skin);
    $result = $upgrader->bulk_upgrade($files);
    return array('success' => !is_wp_error($result), 'updated' => $files);
}

function flotek_sentinel_update_one($request) {
    $plugin = (string) $request->get_param('plugin');
    if ($plugin === '' || strpos($plugin, '..') !== false || !preg_match('/^[A-Za-z0-9._\/-]+\.php$/', $plugin)) {
        return new WP_Error('bad_request', 'Name the plugin file', array('status' => 400));
    }
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
    require_once ABSPATH . 'wp-admin/includes/update.php';
    wp_update_plugins();
    $updates = get_site_transient('update_plugins');
    if (!is_object($updates) || empty($updates->response[$plugin])) {
        return array('success' => true, 'updated' => false, 'detail' => 'That plugin has no update waiting.');
    }
    $skin = new Automatic_Upgrader_Skin();
    $upgrader = new Plugin_Upgrader($skin);
    $result = $upgrader->upgrade($plugin);
    if (is_wp_error($result) || $result === false || $result === null) {
        $message = is_wp_error($result) ? $result->get_error_message() : 'WordPress did not update that plugin.';
        return new WP_Error('failed', $message, array('status' => 500));
    }
    return array('success' => true, 'updated' => true, 'detail' => basename(dirname($plugin)) . ' was updated. The other plugins were left as they are.');
}

add_action('template_redirect', function () {
    if (is_admin() || wp_doing_ajax() || wp_doing_cron() || is_feed() || is_robots() || is_trackback()) {
        return;
    }
    if (defined('REST_REQUEST') && REST_REQUEST) {
        return;
    }
    $day = gmdate('Y-m-d');
    $stats = get_option('flotek_visits', array());
    if (!is_array($stats)) {
        $stats = array();
    }
    if (!isset($stats[$day]) || !is_array($stats[$day])) {
        $stats[$day] = array('views' => 0, 'visitors' => 0, 'pages' => array());
    }
    $stats[$day]['views']++;
    $seen_key = 'flotek_seen_' . $day;
    $seen = get_transient($seen_key);
    if (!is_array($seen)) {
        $seen = array();
    }
    $hash = substr(hash('sha256', flotek_sentinel_ip() . '|' . $day), 0, 12);
    if (!isset($seen[$hash])) {
        if (count($seen) < 1500) {
            $seen[$hash] = 1;
            set_transient($seen_key, $seen, 2 * DAY_IN_SECONDS);
        }
        $stats[$day]['visitors']++;
    }
    $path = isset($_SERVER['REQUEST_URI']) ? strtok((string) $_SERVER['REQUEST_URI'], '?') : '/';
    $path = substr((string) $path, 0, 120);
    if ($path === '') {
        $path = '/';
    }
    if (!isset($stats[$day]['pages']) || !is_array($stats[$day]['pages'])) {
        $stats[$day]['pages'] = array();
    }
    $stats[$day]['pages'][$path] = (isset($stats[$day]['pages'][$path]) ? (int) $stats[$day]['pages'][$path] : 0) + 1;
    if (count($stats[$day]['pages']) > 25) {
        arsort($stats[$day]['pages']);
        $stats[$day]['pages'] = array_slice($stats[$day]['pages'], 0, 15, true);
    }
    ksort($stats);
    if (count($stats) > 30) {
        $stats = array_slice($stats, -30, null, true);
    }
    update_option('flotek_visits', $stats, false);
});

function flotek_sentinel_visit_report() {
    $stats = get_option('flotek_visits', array());
    if (!is_array($stats)) {
        $stats = array();
    }
    $days = array();
    $views = 0;
    $visitors = 0;
    $pages = array();
    foreach ($stats as $day => $row) {
        if (!is_array($row)) {
            continue;
        }
        $view_count = (int) ($row['views'] ?? 0);
        $visitor_count = (int) ($row['visitors'] ?? 0);
        $views += $view_count;
        $visitors += $visitor_count;
        $days[] = array('day' => (string) $day, 'views' => $view_count, 'visitors' => $visitor_count);
        if (!empty($row['pages']) && is_array($row['pages'])) {
            foreach ($row['pages'] as $path => $count) {
                $pages[$path] = (isset($pages[$path]) ? (int) $pages[$path] : 0) + (int) $count;
            }
        }
    }
    arsort($pages);
    $top = array();
    foreach (array_slice($pages, 0, 10, true) as $path => $count) {
        $top[] = array('path' => (string) $path, 'views' => (int) $count);
    }
    $jetpack = array();
    if (function_exists('stats_get_csv')) {
        $rows = stats_get_csv('views', array('days' => 14, 'limit' => 14));
        if (is_array($rows)) {
            foreach ($rows as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $jetpack[] = array('day' => (string) ($row['date'] ?? ''), 'views' => (int) ($row['views'] ?? 0));
            }
        }
    }
    return array(
        'views' => $views,
        'visitors' => $visitors,
        'days' => $days,
        'pages' => $top,
        'jetpack' => $jetpack,
        'note' => 'These are public page views counted by Sentinel on this website. Counting starts the day you upload this file. It is not Google search traffic.',
    );
}

function flotek_sentinel_backup_dir() {
    $dir = WP_CONTENT_DIR . '/flotek-backups';
    if (!is_dir($dir)) {
        wp_mkdir_p($dir);
    }
    if (!file_exists($dir . '/index.php')) {
        file_put_contents($dir . '/index.php', "<?php\n// Silence is golden.\n");
    }
    return $dir;
}

function flotek_sentinel_create_backup() {
    global $wpdb;
    $dir = flotek_sentinel_backup_dir();
    $filename = 'db-' . gmdate('Ymd-His') . '.sql';
    $path = $dir . '/' . $filename;
    $handle = fopen($path, 'w');
    if (!$handle) {
        return new WP_Error('failed', 'Could not write the backup file', array('status' => 500));
    }
    fwrite($handle, "-- Flotek Sentinel backup " . gmdate('c') . "\n");
    $tables = $wpdb->get_col('SHOW TABLES');
    foreach ($tables as $table) {
        $table = (string) $table;
        $create = $wpdb->get_row('SHOW CREATE TABLE `' . esc_sql($table) . '`', ARRAY_N);
        if (!$create) {
            continue;
        }
        fwrite($handle, "\nDROP TABLE IF EXISTS `{$table}`;\n{$create[1]};\n");
        $offset = 0;
        while ($offset < 50000) {
            $rows = $wpdb->get_results($wpdb->prepare('SELECT * FROM `' . esc_sql($table) . '` LIMIT %d OFFSET %d', 200, $offset), ARRAY_A);
            if (!$rows) {
                break;
            }
            foreach ($rows as $row) {
                $values = array();
                foreach ($row as $value) {
                    $values[] = is_null($value) ? 'NULL' : "'" . esc_sql((string) $value) . "'";
                }
                fwrite($handle, 'INSERT INTO `' . $table . '` VALUES (' . implode(',', $values) . ");\n");
            }
            $offset += 200;
            if (count($rows) < 200) {
                break;
            }
        }
    }
    fclose($handle);
    return array(
        'success' => true,
        'filename' => $filename,
        'filesize' => size_format(filesize($path)),
        'location' => $path,
    );
}

function flotek_sentinel_run_sql($sql) {
    global $wpdb;
    if (!is_string($sql) || $sql === '' || strlen($sql) > 20 * 1024 * 1024) {
        return new WP_Error('failed', 'Backup is missing or larger than 20 MB', array('status' => 400));
    }
    $statements = array_filter(array_map('trim', preg_split('/;\s*\n/', $sql)));
    foreach ($statements as $statement) {
        if ($statement === '' || strpos($statement, '--') === 0) {
            continue;
        }
        $wpdb->query($statement);
    }
    return true;
}

function flotek_sentinel_rollback($request) {
    $filename = basename((string) $request->get_param('filename'));
    if (!preg_match('/^(db|upload)-[0-9]{8}-[0-9]{6}\.sql$/', $filename)) {
        return new WP_Error('bad_request', 'That backup name is not valid', array('status' => 400));
    }
    $path = flotek_sentinel_backup_dir() . '/' . $filename;
    if (!is_readable($path)) {
        return new WP_Error('missing', 'Backup file was not found on this site', array('status' => 404));
    }
    $ok = flotek_sentinel_run_sql((string) file_get_contents($path));
    if (is_wp_error($ok)) {
        return $ok;
    }
    return array('success' => true, 'filename' => $filename, 'detail' => 'The database was restored from ' . $filename . '. Plugin files were not changed.');
}

function flotek_sentinel_restore_backup($request) {
    $filename = basename((string) $request->get_param('filename'));
    if (substr($filename, -4) === '.sql') {
        return flotek_sentinel_rollback($request);
    }
    if (!preg_match('/^(site|upload)-[0-9]{8}-[0-9]{6}\.zip$/', $filename)) {
        return new WP_Error('bad_request', 'That backup name is not valid', array('status' => 400));
    }
    $path = flotek_sentinel_backup_dir() . '/' . $filename;
    if (!is_readable($path)) {
        return new WP_Error('missing', 'Backup file was not found on this site', array('status' => 404));
    }
    if (!class_exists('ZipArchive')) {
        return new WP_Error('failed', 'This server does not have ZipArchive', array('status' => 500));
    }
    $zip = new ZipArchive();
    if ($zip->open($path) !== true) {
        return new WP_Error('failed', 'Could not open the zip', array('status' => 500));
    }
    $root = wp_normalize_path(WP_CONTENT_DIR);
    $restored = 0;
    $sql_done = false;
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = str_replace('\\', '/', (string) $zip->getNameIndex($i));
        if ($name === '' || strpos($name, '..') !== false) {
            continue;
        }
        if (substr($name, -4) === '.sql' && strpos($name, '/') === false) {
            $ok = flotek_sentinel_run_sql((string) $zip->getFromIndex($i));
            if (is_wp_error($ok)) {
                $zip->close();
                return $ok;
            }
            $sql_done = true;
            continue;
        }
        if (!preg_match('#^(themes|plugins)/#', $name) || substr($name, -1) === '/') {
            continue;
        }
        if (strpos($name, 'flotek-sentinel-agent.php') !== false) {
            continue;
        }
        $dest = wp_normalize_path(WP_CONTENT_DIR . '/' . $name);
        if (strpos($dest, $root . '/') !== 0) {
            continue;
        }
        wp_mkdir_p(dirname($dest));
        $bytes = $zip->getFromIndex($i);
        if ($bytes === false) {
            continue;
        }
        file_put_contents($dest, $bytes);
        $restored++;
    }
    $zip->close();
    return array(
        'success' => true,
        'detail' => 'Restored ' . $restored . ' plugin and theme files' . ($sql_done ? ' and the database' : '') . ' from ' . $filename . '. The Sentinel file was left in place.',
    );
}

function flotek_sentinel_upload_backup($request) {
    $original = strtolower(basename((string) $request->get_param('filename')));
    $ext = '';
    if (substr($original, -4) === '.zip') {
        $ext = 'zip';
    } elseif (substr($original, -4) === '.sql') {
        $ext = 'sql';
    }
    if ($ext === '') {
        return new WP_Error('bad_request', 'Upload a .sql or .zip file', array('status' => 400));
    }
    $bytes = base64_decode((string) $request->get_param('content'), true);
    if ($bytes === false || strlen($bytes) < 32 || strlen($bytes) > 8 * 1024 * 1024) {
        return new WP_Error('bad_request', 'The file must be between 32 bytes and 8 MB', array('status' => 400));
    }
    if ($ext === 'zip' && substr($bytes, 0, 2) !== 'PK') {
        return new WP_Error('bad_request', 'That is not a zip file', array('status' => 400));
    }
    $filename = 'upload-' . gmdate('Ymd-His') . '.' . $ext;
    $path = flotek_sentinel_backup_dir() . '/' . $filename;
    if (file_put_contents($path, $bytes) === false) {
        return new WP_Error('failed', 'Could not store the upload', array('status' => 500));
    }
    return array(
        'success' => true,
        'filename' => $filename,
        'detail' => 'Stored as ' . $filename . ' in wp-content/flotek-backups/. Press Restore on that row to put it back.',
    );
}

function flotek_sentinel_update_settings($request) {
    $name = sanitize_text_field((string) $request->get_param('site_name'));
    $tagline = sanitize_text_field((string) $request->get_param('tagline'));
    if ($name !== '') {
        update_option('blogname', $name);
    }
    if ($tagline !== '') {
        update_option('blogdescription', $tagline);
    }
    return array(
        'success' => true,
        'site_name' => get_bloginfo('name'),
        'tagline' => get_bloginfo('description'),
    );
}

function flotek_sentinel_disable_plugin($request) {
    $plugin = (string) $request->get_param('plugin');
    if ($plugin === '' || strpos($plugin, '..') !== false) {
        return new WP_Error('bad_request', 'Name the plugin file', array('status' => 400));
    }
    $forced = get_option('flotek_force_disabled', array());
    if (!is_array($forced)) {
        $forced = array();
    }
    if (!in_array($plugin, $forced, true)) {
        $forced[] = $plugin;
        update_option('flotek_force_disabled', $forced, false);
    }
    if (!function_exists('deactivate_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    deactivate_plugins($plugin, true);
    return array('success' => true, 'disabled' => $plugin);
}

function flotek_sentinel_ip() {
    $keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR');
    foreach ($keys as $key) {
        if (empty($_SERVER[$key])) {
            continue;
        }
        $ip = trim(explode(',', (string) $_SERVER[$key])[0]);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }
    return '0.0.0.0';
}

add_action('wp_login_failed', function ($username) {
    $log = get_option('flotek_login_log', array());
    if (!is_array($log)) {
        $log = array();
    }
    array_unshift($log, array(
        'time' => gmdate('c'),
        'ip' => flotek_sentinel_ip(),
        'username' => sanitize_user((string) $username),
        'result' => 'failed',
    ));
    update_option('flotek_login_log', array_slice($log, 0, 80), false);
});

add_filter('authenticate', function ($user, $username, $password) {
    if ($username === '' && $password === '') {
        return $user;
    }
    $ip = flotek_sentinel_ip();
    $allowed = get_option('flotek_allowed_ips', array());
    $blocked = get_option('flotek_blocked_ips', array());
    if (is_array($allowed) && in_array($ip, $allowed, true)) {
        return $user;
    }
    if (is_array($blocked) && in_array($ip, $blocked, true)) {
        return new WP_Error('flotek_blocked', 'This address is blocked by Flotek Sentinel.');
    }
    return $user;
}, 1, 3);

add_filter('auto_update_core', function () {
    return (bool) get_option('flotek_auto_core');
});
add_filter('auto_update_plugin', function () {
    return (bool) get_option('flotek_auto_plugins');
});
add_filter('auto_update_theme', function () {
    return (bool) get_option('flotek_auto_themes');
});

function flotek_sentinel_critical_files() {
    $root = ABSPATH;
    $config = file_exists($root . 'wp-config.php') ? $root . 'wp-config.php' : dirname($root) . '/wp-config.php';
    return array(
        'wp-config.php' => $config,
        'index.php' => $root . 'index.php',
        '.htaccess' => $root . '.htaccess',
        'robots.txt' => $root . 'robots.txt',
    );
}

function flotek_sentinel_file_audit() {
    $current = array();
    foreach (flotek_sentinel_critical_files() as $name => $path) {
        $current[$name] = is_readable($path) ? hash_file('sha256', $path) : '';
    }
    $baseline = get_option('flotek_file_baseline', array());
    if (!is_array($baseline) || !$baseline) {
        update_option('flotek_file_baseline', $current, false);
        return array('saved_baseline' => true, 'files' => $current, 'changes' => array());
    }
    $changes = array();
    foreach ($current as $name => $hash) {
        $old = array_key_exists($name, $baseline) ? (string) $baseline[$name] : null;
        if ($old === null && $hash !== '') {
            $changes[] = array('file' => $name, 'change' => 'added', 'detail' => $name . ' was added. It was not on the server when the baseline was saved.');
        } elseif ($old !== null && $old !== '' && $hash === '') {
            $changes[] = array('file' => $name, 'change' => 'removed', 'detail' => $name . ' was removed from the server.');
        } elseif ($old !== null && $hash !== '' && $old !== $hash) {
            $changes[] = array(
                'file' => $name,
                'change' => 'modified',
                'detail' => $name . ' was modified. Old fingerprint ' . substr($old, 0, 12) . ', new fingerprint ' . substr($hash, 0, 12) . '.',
            );
        }
    }
    return array('saved_baseline' => false, 'files' => $current, 'changes' => $changes);
}

function flotek_sentinel_affected($version, $rule) {
    $max = isset($rule['max_version']) ? (string) $rule['max_version'] : '';
    $op = isset($rule['max_operator']) ? (string) $rule['max_operator'] : 'lt';
    if ($max === '') {
        return false;
    }
    if ($op === 'le') {
        return version_compare($version, $max, '<=');
    }
    return version_compare($version, $max, '<');
}

function flotek_sentinel_security() {
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $vulns = get_transient('flotek_vulns');
    if (!is_array($vulns)) {
        $vulns = array();
        $n = 0;
        foreach (get_plugins() as $file => $plugin) {
            if ($n++ >= 12) {
                break;
            }
            $slug = dirname($file);
            if ($slug === '.') {
                $slug = basename($file, '.php');
            }
            $res = wp_remote_get('https://www.wpvulnerability.net/plugin/' . rawurlencode($slug), array(
                'timeout' => 8,
                'headers' => array('Accept' => 'application/json'),
            ));
            if (is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200) {
                continue;
            }
            $body = json_decode(wp_remote_retrieve_body($res), true);
            $list = $body['data']['vulnerability'] ?? array();
            if (!is_array($list)) {
                continue;
            }
            foreach ($list as $item) {
                if (!flotek_sentinel_affected($plugin['Version'], $item['operator'] ?? array())) {
                    continue;
                }
                $cve = '';
                foreach (($item['source'] ?? array()) as $source) {
                    if (!empty($source['id']) && strpos($source['id'], 'CVE-') === 0) {
                        $cve = $source['id'];
                        break;
                    }
                }
                $vulns[] = array(
                    'plugin' => $plugin['Name'],
                    'slug' => $slug,
                    'version' => $plugin['Version'],
                    'title' => $item['name'] ?? $slug,
                    'cve' => $cve,
                );
                break;
            }
        }
        set_transient('flotek_vulns', $vulns, 12 * HOUR_IN_SECONDS);
    }
    $log = get_option('flotek_login_log', array());
    return array(
        'files' => flotek_sentinel_file_audit(),
        'vulns' => $vulns,
        'logins' => is_array($log) ? array_slice($log, 0, 20) : array(),
        'blocked' => array_values((array) get_option('flotek_blocked_ips', array())),
        'allowed' => array_values((array) get_option('flotek_allowed_ips', array())),
        'policy' => array(
            'core' => (bool) get_option('flotek_auto_core'),
            'plugins' => (bool) get_option('flotek_auto_plugins'),
            'themes' => (bool) get_option('flotek_auto_themes'),
        ),
        'theme' => wp_get_theme()->get('Name'),
        'supabase' => get_option('flotek_supabase_url', '') !== '',
    );
}

function flotek_sentinel_update_policy($request) {
    update_option('flotek_auto_core', (bool) $request->get_param('core'), false);
    update_option('flotek_auto_plugins', (bool) $request->get_param('plugins'), false);
    update_option('flotek_auto_themes', (bool) $request->get_param('themes'), false);
    return array('success' => true);
}

function flotek_sentinel_update_core() {
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/update.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
    wp_version_check();
    $core = get_site_transient('update_core');
    $offer = (is_object($core) && !empty($core->updates)) ? $core->updates[0] : null;
    if (!$offer || empty($offer->response) || $offer->response === 'latest') {
        return array('success' => true, 'updated' => false, 'detail' => 'WordPress core is already current.');
    }
    $skin = new Automatic_Upgrader_Skin();
    $upgrader = new Core_Upgrader($skin);
    $result = $upgrader->upgrade($offer);
    if (is_wp_error($result)) {
        return new WP_Error('failed', $result->get_error_message(), array('status' => 500));
    }
    return array('success' => true, 'updated' => true, 'detail' => 'WordPress core update was pushed.');
}

function flotek_sentinel_update_themes() {
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/theme.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
    require_once ABSPATH . 'wp-admin/includes/update.php';
    wp_update_themes();
    $updates = get_site_transient('update_themes');
    $slugs = array();
    if (is_object($updates) && !empty($updates->response)) {
        $slugs = array_keys($updates->response);
    }
    if (!$slugs) {
        return array('success' => true, 'updated' => array());
    }
    $skin = new Automatic_Upgrader_Skin();
    $upgrader = new Theme_Upgrader($skin);
    $result = $upgrader->bulk_upgrade($slugs);
    return array('success' => !is_wp_error($result), 'updated' => $slugs);
}

function flotek_sentinel_ip_list($key, $ip, $add) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return new WP_Error('bad_request', 'That is not an IP address', array('status' => 400));
    }
    $list = get_option($key, array());
    if (!is_array($list)) {
        $list = array();
    }
    $list = array_values(array_filter($list, function ($item) use ($ip) {
        return $item !== $ip;
    }));
    if ($add) {
        $list[] = $ip;
    }
    update_option($key, $list, false);
    return array('success' => true, 'list' => $list);
}

function flotek_sentinel_block_ip($request) {
    $ip = (string) $request->get_param('ip');
    $block = (bool) $request->get_param('block');
    return flotek_sentinel_ip_list('flotek_blocked_ips', $ip, $block);
}

function flotek_sentinel_allow_ip($request) {
    $ip = (string) $request->get_param('ip');
    $allow = (bool) $request->get_param('allow');
    return flotek_sentinel_ip_list('flotek_allowed_ips', $ip, $allow);
}

function flotek_sentinel_accept_files() {
    delete_option('flotek_file_baseline');
    return flotek_sentinel_file_audit();
}

function flotek_sentinel_seo() {
    $robots_path = ABSPATH . 'robots.txt';
    $robots = is_readable($robots_path) ? (string) file_get_contents($robots_path) : '';
    $blocks = (bool) preg_match('/User-agent:\s*\*\s+Disallow:\s*\/\s*($|\r|\n)/i', $robots)
        || (bool) preg_match('/User-agent:\s*Googlebot[\s\S]{0,200}Disallow:\s*\/\s*($|\r|\n)/i', $robots);
    $sitemaps = array();
    foreach (array('/wp-sitemap.xml', '/sitemap.xml', '/sitemap_index.xml') as $path) {
        $res = wp_remote_head(home_url($path), array('timeout' => 8, 'redirection' => 3));
        $sitemaps[] = array(
            'url' => home_url($path),
            'status' => is_wp_error($res) ? 0 : (int) wp_remote_retrieve_response_code($res),
        );
    }
    $home = wp_remote_get(home_url('/'), array('timeout' => 12));
    $html = is_wp_error($home) ? '' : (string) wp_remote_retrieve_body($home);
    $host = wp_parse_url(home_url(), PHP_URL_HOST);
    preg_match_all('/href=["\']([^"\']+)["\']/i', $html, $hrefs);
    $broken = array();
    $seen = array();
    foreach ($hrefs[1] as $href) {
        if (count($broken) >= 12 || count($seen) >= 25) {
            break;
        }
        if ($href === '' || $href[0] === '#' || strpos($href, 'mailto:') === 0 || strpos($href, 'tel:') === 0) {
            continue;
        }
        if (strpos($href, '//') === 0) {
            $href = 'https:' . $href;
        } elseif ($href[0] === '/') {
            $href = home_url($href);
        } elseif (!preg_match('#^https?://#', $href)) {
            continue;
        }
        $href = strtok($href, '#');
        $link_host = wp_parse_url($href, PHP_URL_HOST);
        if ($link_host && $link_host !== $host) {
            continue;
        }
        if (isset($seen[$href])) {
            continue;
        }
        $seen[$href] = true;
        $res = wp_remote_head($href, array('timeout' => 6, 'redirection' => 5));
        $code = is_wp_error($res) ? 0 : (int) wp_remote_retrieve_response_code($res);
        if ($code === 0 || $code >= 400) {
            $broken[] = array('url' => $href, 'status' => $code);
        }
    }
    preg_match_all('/<img[^>]+src=["\']([^"\']+)["\']/i', $html, $imgs);
    $images = array();
    foreach (array_slice($imgs[1], 0, 12) as $src) {
        if (strpos($src, '//') === 0) {
            $src = 'https:' . $src;
        } elseif ($src !== '' && $src[0] === '/') {
            $src = home_url($src);
        }
        if (!preg_match('#^https?://#', $src)) {
            continue;
        }
        $res = wp_remote_head($src, array('timeout' => 6, 'redirection' => 3));
        $code = is_wp_error($res) ? 0 : (int) wp_remote_retrieve_response_code($res);
        if ($code === 0 || $code >= 400) {
            $images[] = array('url' => $src, 'status' => $code);
        }
    }
    return array(
        'robots_present' => $robots !== '',
        'robots_blocks_google' => $blocks,
        'sitemaps' => $sitemaps,
        'broken_links' => $broken,
        'broken_images' => $images,
    );
}

function flotek_sentinel_relay() {
    $domain = wp_parse_url(home_url(), PHP_URL_HOST);
    $mx = array();
    $host = $domain;
    if (function_exists('getmxrr') && getmxrr($domain, $mx) && !empty($mx[0])) {
        $host = $mx[0];
    }
    $fp = @fsockopen($host, 25, $errno, $errstr, 8);
    if (!$fp) {
        return array('tested' => false, 'host' => $host, 'open' => false, 'detail' => 'Port 25 could not be opened from this server. ' . $errstr);
    }
    stream_set_timeout($fp, 8);
    $banner = fgets($fp, 512);
    fwrite($fp, "EHLO sentinel.flotek.io\r\n");
    $ehlo = '';
    for ($i = 0; $i < 12; $i++) {
        $line = fgets($fp, 512);
        if ($line === false) {
            break;
        }
        $ehlo .= $line;
        if (isset($line[3]) && $line[3] === ' ') {
            break;
        }
    }
    fwrite($fp, "MAIL FROM:<audit@sentinel.flotek.io>\r\n");
    fgets($fp, 512);
    fwrite($fp, "RCPT TO:<relay-test@example.net>\r\n");
    $rcpt = (string) fgets($fp, 512);
    fwrite($fp, "RSET\r\n");
    fgets($fp, 512);
    fwrite($fp, "QUIT\r\n");
    fclose($fp);
    $open = strpos($rcpt, '250') === 0;
    return array(
        'tested' => true,
        'host' => $host,
        'open' => $open,
        'detail' => $open ? 'Open relay: ' . $host . ' accepted mail for an outside address.' : $host . ' refused an outside recipient.',
        'banner' => trim((string) $banner),
    );
}

function flotek_sentinel_journey() {
    $steps = array();
    foreach (array('/', '/shop/', '/cart/', '/checkout/', '/my-account/') as $path) {
        $res = wp_remote_get(home_url($path), array('timeout' => 10, 'redirection' => 5));
        $code = is_wp_error($res) ? 0 : (int) wp_remote_retrieve_response_code($res);
        $steps[] = array('path' => $path, 'status' => $code, 'ok' => $code >= 200 && $code < 400);
    }
    return array(
        'woocommerce' => class_exists('WooCommerce'),
        'steps' => $steps,
        'detail' => 'Each step is a real request to the site. A scripted browser checkout is not run from this page.',
    );
}

function flotek_sentinel_backup_settings($request) {
    update_option('flotek_supabase_url', esc_url_raw((string) $request->get_param('supabase_url')), false);
    $key = (string) $request->get_param('supabase_key');
    if ($key !== '') {
        update_option('flotek_supabase_key', $key, false);
    }
    $bucket = sanitize_file_name((string) $request->get_param('bucket'));
    update_option('flotek_supabase_bucket', $bucket !== '' ? $bucket : 'sentinel', false);
    return array('success' => true);
}

function flotek_sentinel_full_backup() {
    if (!class_exists('ZipArchive')) {
        return new WP_Error('failed', 'This server does not have ZipArchive', array('status' => 500));
    }
    $dir = flotek_sentinel_backup_dir();
    $sql_name = 'db-' . gmdate('Ymd-His') . '.sql';
    $sql = flotek_sentinel_create_backup();
    if (is_wp_error($sql)) {
        return $sql;
    }
    $zip_name = 'site-' . gmdate('Ymd-His') . '.zip';
    $zip_path = $dir . '/' . $zip_name;
    $zip = new ZipArchive();
    if ($zip->open($zip_path, ZipArchive::CREATE) !== true) {
        return new WP_Error('failed', 'Could not create the zip file', array('status' => 500));
    }
    $sql_path = $dir . '/' . $sql['filename'];
    if (is_readable($sql_path)) {
        $zip->addFile($sql_path, $sql['filename']);
    }
    $roots = array('themes', 'plugins', 'mu-plugins');
    foreach ($roots as $folder) {
        $base = WP_CONTENT_DIR . '/' . $folder;
        if (!is_dir($base)) {
            continue;
        }
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS));
        $added = 0;
        foreach ($iterator as $file) {
            if ($added >= 400 || !$file->isFile() || $file->getSize() > 8 * 1024 * 1024) {
                continue;
            }
            $zip->addFile($file->getPathname(), $folder . '/' . substr($file->getPathname(), strlen($base) + 1));
            $added++;
        }
    }
    $zip->close();
    $remote = '';
    $url = untrailingslashit((string) get_option('flotek_supabase_url', ''));
    $key = (string) get_option('flotek_supabase_key', '');
    $bucket = (string) get_option('flotek_supabase_bucket', 'sentinel');
    if ($url !== '' && $key !== '') {
        $upload = wp_remote_post($url . '/storage/v1/object/' . rawurlencode($bucket) . '/' . rawurlencode($zip_name), array(
            'timeout' => 60,
            'headers' => array(
                'Authorization' => 'Bearer ' . $key,
                'apikey' => $key,
                'Content-Type' => 'application/zip',
                'x-upsert' => 'true',
            ),
            'body' => file_get_contents($zip_path),
        ));
        $remote = is_wp_error($upload) ? $upload->get_error_message() : 'Uploaded to Supabase bucket ' . $bucket;
    }
    return array(
        'success' => true,
        'filename' => $zip_name,
        'filesize' => size_format(filesize($zip_path)),
        'remote' => $remote,
        'detail' => 'Zip holds the database, themes and plugins. Uploads are left out so the request can finish. ' . $remote,
    );
}

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
        array('create-user', 'POST', 'flotek_sentinel_create_user'),
        array('reset-password', 'POST', 'flotek_sentinel_reset_password'),
        array('delete-user', 'POST', 'flotek_sentinel_delete_user'),
        array('update-plugins', 'POST', 'flotek_sentinel_update_plugins'),
        array('create-backup', 'POST', 'flotek_sentinel_create_backup'),
        array('rollback', 'POST', 'flotek_sentinel_rollback'),
        array('disable-plugin', 'POST', 'flotek_sentinel_disable_plugin'),
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
            if (substr($file, -4) !== '.sql') {
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
        'site_url' => home_url(),
        'wp_version' => get_bloginfo('version'),
        'php_version' => PHP_VERSION,
        'theme' => array('name' => $theme->get('Name'), 'version' => $theme->get('Version')),
        'plugins' => $plugins,
        'users' => $users,
        'backups' => $backups,
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

function flotek_sentinel_rollback($request) {
    global $wpdb;
    $filename = basename((string) $request->get_param('filename'));
    if (!preg_match('/^db-[0-9]{8}-[0-9]{6}\.sql$/', $filename)) {
        return new WP_Error('bad_request', 'That backup name is not valid', array('status' => 400));
    }
    $path = flotek_sentinel_backup_dir() . '/' . $filename;
    if (!is_readable($path)) {
        return new WP_Error('missing', 'Backup file was not found on this site', array('status' => 404));
    }
    $sql = file_get_contents($path);
    if ($sql === false || strlen($sql) > 20 * 1024 * 1024) {
        return new WP_Error('failed', 'Backup is missing or larger than 20 MB', array('status' => 400));
    }
    $statements = array_filter(array_map('trim', preg_split('/;\s*\n/', $sql)));
    foreach ($statements as $statement) {
        if ($statement === '' || strpos($statement, '--') === 0) {
            continue;
        }
        $wpdb->query($statement);
    }
    return array('success' => true, 'filename' => $filename);
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

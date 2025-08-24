<?php
/**
 * Admin Settings Page
 * Configuration options for the Mardi Gras Glossary
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Handle form submission
if (isset($_POST['submit'])) {
    check_admin_referer('mgg_settings_nonce');
    
    update_option('mgg_api_url', sanitize_url($_POST['mgg_api_url']));
    update_option('mgg_cache_duration', intval($_POST['mgg_cache_duration']));
    update_option('mgg_sync_frequency', sanitize_text_field($_POST['mgg_sync_frequency']));
    
    echo '<div class="notice notice-success"><p>Settings saved successfully!</p></div>';
}

// Handle cache clear
if (isset($_POST['clear_cache'])) {
    check_admin_referer('mgg_cache_nonce');
    
    // Delete all glossary-related transients
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_mgg_%' OR option_name LIKE '_transient_timeout_mgg_%'");
    
    echo '<div class="notice notice-success"><p>Cache cleared successfully!</p></div>';
}

// Get current settings
$api_url = get_option('mgg_api_url', 'https://your-mardi-gras-api.railway.app');
$cache_duration = get_option('mgg_cache_duration', 3600);
$sync_frequency = get_option('mgg_sync_frequency', 'hourly');

// Test API connection
$glossary = new MardiGrasGlossary();
$api_test = $glossary->fetch_categories();
$api_working = !empty($api_test['categories']);
?>

<div class="wrap">
    <h1>Mardi Gras Glossary Settings</h1>
    
    <!-- API Status -->
    <div class="card">
        <h2>API Connection Status</h2>
        <p>
            Status: 
            <?php if ($api_working): ?>
                <span style="color: green; font-weight: bold;">✓ Connected</span>
                <br>
                <small>Successfully connected to your Mardi Gras API. Found <?php echo count($api_test['categories']); ?> categories.</small>
            <?php else: ?>
                <span style="color: red; font-weight: bold;">✗ Connection Failed</span>
                <br>
                <small>Unable to connect to the API. Please check your API URL and ensure the service is running.</small>
            <?php endif; ?>
        </p>
    </div>
    
    <!-- Settings Form -->
    <form method="post" action="">
        <?php wp_nonce_field('mgg_settings_nonce'); ?>
        
        <table class="form-table">
            <tr>
                <th scope="row">
                    <label for="mgg_api_url">API Base URL</label>
                </th>
                <td>
                    <input type="url" 
                           id="mgg_api_url" 
                           name="mgg_api_url" 
                           value="<?php echo esc_attr($api_url); ?>" 
                           class="regular-text" 
                           required />
                    <p class="description">
                        The base URL of your Mardi Gras API (e.g., https://your-app.railway.app)
                    </p>
                </td>
            </tr>
            
            <tr>
                <th scope="row">
                    <label for="mgg_cache_duration">Cache Duration (seconds)</label>
                </th>
                <td>
                    <input type="number" 
                           id="mgg_cache_duration" 
                           name="mgg_cache_duration" 
                           value="<?php echo esc_attr($cache_duration); ?>" 
                           min="300" 
                           max="86400" 
                           class="small-text" />
                    <p class="description">
                        How long to cache API responses (300 = 5 minutes, 3600 = 1 hour, 86400 = 24 hours)
                    </p>
                </td>
            </tr>
            
            <tr>
                <th scope="row">
                    <label for="mgg_sync_frequency">Sync Frequency</label>
                </th>
                <td>
                    <select id="mgg_sync_frequency" name="mgg_sync_frequency">
                        <option value="hourly" <?php selected($sync_frequency, 'hourly'); ?>>Hourly</option>
                        <option value="twicedaily" <?php selected($sync_frequency, 'twicedaily'); ?>>Twice Daily</option>
                        <option value="daily" <?php selected($sync_frequency, 'daily'); ?>>Daily</option>
                        <option value="weekly" <?php selected($sync_frequency, 'weekly'); ?>>Weekly</option>
                    </select>
                    <p class="description">
                        How often to automatically sync data from the API (affects background updates)
                    </p>
                </td>
            </tr>
        </table>
        
        <?php submit_button('Save Settings'); ?>
    </form>
    
    <!-- Cache Management -->
    <div class="card">
        <h2>Cache Management</h2>
        <p>Clear the cache to force fresh data from your API. Use this if you've updated terms in your API and want them to appear immediately.</p>
        
        <form method="post" action="" style="display: inline;">
            <?php wp_nonce_field('mgg_cache_nonce'); ?>
            <input type="submit" name="clear_cache" class="button" value="Clear Cache" />
        </form>
    </div>
    
    <!-- Usage Instructions -->
    <div class="card">
        <h2>How to Use</h2>
        <h3>Method 1: Shortcode (Recommended)</h3>
        <p>Add the glossary to any page or post using this shortcode:</p>
        <code>[mardi_gras_glossary]</code>
        
        <h3>Method 2: Direct URL</h3>
        <p>The plugin automatically creates these URLs on your site:</p>
        <ul>
            <li><strong>Main Glossary:</strong> <code><?php echo home_url('/mardi-gras-glossary/'); ?></code></li>
            <li><strong>Category Pages:</strong> <code><?php echo home_url('/mardi-gras-glossary/category/krewes/'); ?></code></li>
            <li><strong>Individual Terms:</strong> <code><?php echo home_url('/mardi-gras-glossary/king-cake/'); ?></code></li>
        </ul>
        
        <h3>Search Engine Optimization</h3>
        <p>The plugin automatically:</p>
        <ul>
            <li>Creates SEO-friendly URLs for all terms</li>
            <li>Adds proper meta descriptions</li>
            <li>Includes structured data markup</li>
            <li>Generates XML sitemaps (if using an SEO plugin)</li>
        </ul>
    </div>
    
    <!-- Statistics -->
    <?php if ($api_working): ?>
    <div class="card">
        <h2>Current Statistics</h2>
        <?php
        $stats = $glossary->fetch_terms(array('limit' => 1));
        $categories = count($api_test['categories']);
        $total_terms = 0;
        
        // Get total count from API
        $all_terms = $glossary->fetch_terms(array('limit' => 1000)); // High limit to get count
        $total_terms = count($all_terms['terms'] ?? array());
        ?>
        <p>
            <strong>Categories:</strong> <?php echo $categories; ?><br>
            <strong>Terms:</strong> <?php echo $total_terms; ?><br>
            <strong>Last Cache Update:</strong> 
            <?php
            $last_cache = get_option('mgg_last_cache_update');
            if ($last_cache) {
                echo date('M j, Y g:i A', $last_cache);
            } else {
                echo 'Never';
            }
            ?>
        </p>
    </div>
    <?php endif; ?>
    
    <!-- Troubleshooting -->
    <div class="card">
        <h2>Troubleshooting</h2>
        <details>
            <summary>Common Issues</summary>
            <dl>
                <dt>Terms not showing up</dt>
                <dd>Check that your API URL is correct and the service is running. Try clearing the cache.</dd>
                
                <dt>404 errors on glossary pages</dt>
                <dd>Go to Settings → Permalinks and click "Save Changes" to flush rewrite rules.</dd>
                
                <dt>Styling doesn't match my theme</dt>
                <dd>The plugin is designed for Inspiro theme. You may need to add custom CSS for other themes.</dd>
                
                <dt>Slow loading</dt>
                <dd>Increase the cache duration or check your API server performance.</dd>
            </dl>
        </details>
    </div>
    
</div>

<style>
.card {
    background: white;
    border: 1px solid #ccd0d4;
    border-radius: 4px;
    padding: 20px;
    margin: 20px 0;
    box-shadow: 0 1px 1px rgba(0,0,0,.04);
}

.card h2 {
    margin-top: 0;
}

code {
    background: #f1f1f1;
    padding: 2px 4px;
    font-family: Consolas, Monaco, monospace;
}

details {
    margin-top: 10px;
}

dt {
    font-weight: bold;
    margin-top: 10px;
}

dd {
    margin-left: 0;
    margin-bottom: 10px;
    color: #666;
}
</style>
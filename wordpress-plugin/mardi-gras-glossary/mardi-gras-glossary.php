<?php
/**
 * Plugin Name: Mardi Gras Glossary
 * Plugin URI: https://your-site.com/mardi-gras-glossary
 * Description: A comprehensive Mardi Gras terminology glossary with search, filtering, and SEO optimization. Integrates with your Mardi Gras API and Inspiro theme.
 * Version: 1.0.0
 * Author: Your Name
 * License: GPL v2 or later
 * Text Domain: mardi-gras-glossary
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('MGG_PLUGIN_URL', plugin_dir_url(__FILE__));
define('MGG_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('MGG_VERSION', '1.0.0');

// Main plugin class
class MardiGrasGlossary {
    
    private $api_base_url;
    
    public function __construct() {
        $this->api_base_url = get_option('mgg_api_url', 'https://your-mardi-gras-api.railway.app');
        
        add_action('init', array($this, 'init'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('admin_menu', array($this, 'admin_menu'));
        add_action('admin_init', array($this, 'admin_init'));
        
        // Register activation/deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
        
        // Add rewrite rules
        add_action('init', array($this, 'add_rewrite_rules'));
        add_filter('query_vars', array($this, 'add_query_vars'));
        add_action('template_redirect', array($this, 'template_redirect'));
    }
    
    public function init() {
        // Create custom post type for SEO benefits
        $this->register_post_type();
        
        // Add shortcode for main glossary page
        add_shortcode('mardi_gras_glossary', array($this, 'glossary_shortcode'));
    }
    
    public function register_post_type() {
        $args = array(
            'public' => true,
            'label' => 'Glossary Terms',
            'labels' => array(
                'name' => 'Glossary Terms',
                'singular_name' => 'Glossary Term',
                'add_new' => 'Add New Term',
                'add_new_item' => 'Add New Glossary Term',
                'edit_item' => 'Edit Glossary Term',
                'new_item' => 'New Glossary Term',
                'view_item' => 'View Glossary Term',
                'search_items' => 'Search Glossary Terms',
                'not_found' => 'No glossary terms found',
                'not_found_in_trash' => 'No glossary terms found in trash'
            ),
            'supports' => array('title', 'editor', 'excerpt', 'custom-fields'),
            'has_archive' => false,
            'rewrite' => array('slug' => 'mardi-gras-glossary', 'with_front' => false),
            'show_in_rest' => true,
            'menu_icon' => 'dashicons-book-alt'
        );
        
        register_post_type('mgg_term', $args);
        
        // Register taxonomy for categories
        register_taxonomy('mgg_category', 'mgg_term', array(
            'hierarchical' => true,
            'labels' => array(
                'name' => 'Glossary Categories',
                'singular_name' => 'Glossary Category'
            ),
            'rewrite' => array('slug' => 'mardi-gras-glossary/category'),
            'show_in_rest' => true
        ));
    }
    
    public function add_rewrite_rules() {
        // Main glossary page
        add_rewrite_rule(
            '^mardi-gras-glossary/?$',
            'index.php?mgg_page=main',
            'top'
        );
        
        // Category pages
        add_rewrite_rule(
            '^mardi-gras-glossary/category/([^/]+)/?$',
            'index.php?mgg_page=category&mgg_category=$matches[1]',
            'top'
        );
        
        // Individual term pages
        add_rewrite_rule(
            '^mardi-gras-glossary/([^/]+)/?$',
            'index.php?mgg_page=term&mgg_term=$matches[1]',
            'top'
        );
    }
    
    public function add_query_vars($vars) {
        $vars[] = 'mgg_page';
        $vars[] = 'mgg_category';
        $vars[] = 'mgg_term';
        return $vars;
    }
    
    public function template_redirect() {
        $mgg_page = get_query_var('mgg_page');
        
        if ($mgg_page) {
            switch ($mgg_page) {
                case 'main':
                    $this->load_main_template();
                    break;
                case 'category':
                    $this->load_category_template();
                    break;
                case 'term':
                    $this->load_term_template();
                    break;
            }
            exit;
        }
    }
    
    public function enqueue_scripts() {
        if ($this->is_glossary_page()) {
            wp_enqueue_style('mgg-styles', MGG_PLUGIN_URL . 'assets/css/glossary.css', array(), MGG_VERSION);
            wp_enqueue_script('mgg-scripts', MGG_PLUGIN_URL . 'assets/js/glossary.js', array('jquery'), MGG_VERSION, true);
            
            // Localize script for AJAX
            wp_localize_script('mgg-scripts', 'mgg_ajax', array(
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('mgg_nonce'),
                'api_url' => $this->api_base_url
            ));
        }
    }
    
    private function is_glossary_page() {
        return get_query_var('mgg_page') || is_singular('mgg_term') || has_shortcode(get_post()->post_content ?? '', 'mardi_gras_glossary');
    }
    
    public function glossary_shortcode($atts) {
        $atts = shortcode_atts(array(
            'view' => 'main',
            'category' => '',
            'limit' => 50
        ), $atts);
        
        ob_start();
        $this->render_main_glossary($atts);
        return ob_get_clean();
    }
    
    private function load_main_template() {
        $this->load_header();
        $this->render_main_glossary();
        $this->load_footer();
    }
    
    private function load_category_template() {
        $category = get_query_var('mgg_category');
        $this->load_header();
        $this->render_category_page($category);
        $this->load_footer();
    }
    
    private function load_term_template() {
        $term_slug = get_query_var('mgg_term');
        $this->load_header();
        $this->render_term_page($term_slug);
        $this->load_footer();
    }
    
    private function load_header() {
        get_header();
        echo '<div class="mgg-container">';
    }
    
    private function load_footer() {
        echo '</div>';
        get_footer();
    }
    
    private function render_main_glossary($atts = array()) {
        include MGG_PLUGIN_PATH . 'templates/main-glossary.php';
    }
    
    private function render_category_page($category) {
        include MGG_PLUGIN_PATH . 'templates/category-page.php';
    }
    
    private function render_term_page($term_slug) {
        include MGG_PLUGIN_PATH . 'templates/term-page.php';
    }
    
    // Admin functions
    public function admin_menu() {
        add_options_page(
            'Mardi Gras Glossary Settings',
            'Mardi Gras Glossary',
            'manage_options',
            'mardi-gras-glossary',
            array($this, 'admin_page')
        );
    }
    
    public function admin_init() {
        register_setting('mgg_settings', 'mgg_api_url');
        register_setting('mgg_settings', 'mgg_sync_frequency');
        register_setting('mgg_settings', 'mgg_cache_duration');
    }
    
    public function admin_page() {
        include MGG_PLUGIN_PATH . 'admin/settings.php';
    }
    
    // API integration functions
    public function fetch_terms($params = array()) {
        $cache_key = 'mgg_terms_' . md5(serialize($params));
        $cached_data = get_transient($cache_key);
        
        if ($cached_data !== false) {
            return $cached_data;
        }
        
        $url = $this->api_base_url . '/glossary/terms';
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }
        
        $response = wp_remote_get($url);
        if (is_wp_error($response)) {
            return array('terms' => array(), 'count' => 0);
        }
        
        $data = json_decode(wp_remote_retrieve_body($response), true);
        
        // Cache for 1 hour by default
        $cache_duration = get_option('mgg_cache_duration', 3600);
        set_transient($cache_key, $data, $cache_duration);
        
        return $data;
    }
    
    public function fetch_term($slug) {
        $cache_key = 'mgg_term_' . $slug;
        $cached_data = get_transient($cache_key);
        
        if ($cached_data !== false) {
            return $cached_data;
        }
        
        $url = $this->api_base_url . '/glossary/term/' . $slug;
        $response = wp_remote_get($url);
        
        if (is_wp_error($response)) {
            return null;
        }
        
        $data = json_decode(wp_remote_retrieve_body($response), true);
        
        // Cache for 1 hour
        set_transient($cache_key, $data, 3600);
        
        return $data;
    }
    
    public function fetch_categories() {
        $cache_key = 'mgg_categories';
        $cached_data = get_transient($cache_key);
        
        if ($cached_data !== false) {
            return $cached_data;
        }
        
        $url = $this->api_base_url . '/glossary/categories';
        $response = wp_remote_get($url);
        
        if (is_wp_error($response)) {
            return array('categories' => array());
        }
        
        $data = json_decode(wp_remote_retrieve_body($response), true);
        
        // Cache for 4 hours (categories change less frequently)
        set_transient($cache_key, $data, 14400);
        
        return $data;
    }
    
    // Activation/Deactivation
    public function activate() {
        $this->add_rewrite_rules();
        flush_rewrite_rules();
        
        // Set default options
        add_option('mgg_api_url', 'https://your-mardi-gras-api.railway.app');
        add_option('mgg_cache_duration', 3600);
    }
    
    public function deactivate() {
        flush_rewrite_rules();
    }
}

// Initialize the plugin
new MardiGrasGlossary();

// AJAX handlers
add_action('wp_ajax_mgg_search_terms', 'mgg_ajax_search_terms');
add_action('wp_ajax_nopriv_mgg_search_terms', 'mgg_ajax_search_terms');

function mgg_ajax_search_terms() {
    check_ajax_referer('mgg_nonce', 'nonce');
    
    $search = sanitize_text_field($_POST['search'] ?? '');
    $category = sanitize_text_field($_POST['category'] ?? '');
    $difficulty = sanitize_text_field($_POST['difficulty'] ?? '');
    $sort = sanitize_text_field($_POST['sort'] ?? 'term');
    $limit = intval($_POST['limit'] ?? 50);
    
    $glossary = new MardiGrasGlossary();
    $params = array();
    
    if ($search) $params['search'] = $search;
    if ($category) $params['category'] = $category;
    if ($difficulty) $params['difficulty'] = $difficulty;
    if ($limit) $params['limit'] = $limit;
    
    $data = $glossary->fetch_terms($params);
    
    wp_send_json_success($data);
}
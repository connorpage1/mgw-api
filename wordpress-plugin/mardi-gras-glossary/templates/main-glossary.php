<?php
/**
 * Main Glossary Template
 * Displays the searchable, sortable glossary interface
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get initial data
$glossary = new MardiGrasGlossary();
$categories_data = $glossary->fetch_categories();
$categories = $categories_data['categories'] ?? array();

// Get URL parameters for initial state
$initial_search = sanitize_text_field($_GET['search'] ?? '');
$initial_category = sanitize_text_field($_GET['category'] ?? '');
$initial_difficulty = sanitize_text_field($_GET['difficulty'] ?? '');
$initial_sort = sanitize_text_field($_GET['sort'] ?? 'term');

// Fetch initial terms
$params = array('limit' => 50);
if ($initial_search) $params['search'] = $initial_search;
if ($initial_category) $params['category'] = $initial_category;
if ($initial_difficulty) $params['difficulty'] = $initial_difficulty;

$terms_data = $glossary->fetch_terms($params);
$terms = $terms_data['terms'] ?? array();
$total_count = $terms_data['count'] ?? 0;
?>

<div class="mgg-main-glossary">
    
    <!-- Hero Section with Inspiro Styling -->
    <div class="mgg-hero-section">
        <div class="mgg-hero-content">
            <h1 class="mgg-main-title">Complete Mardi Gras Glossary</h1>
            <p class="mgg-hero-subtitle">Your comprehensive guide to Carnival and Mardi Gras terminology, traditions, and culture</p>
        </div>
    </div>
    
    <!-- Search and Filter Controls -->
    <div class="mgg-controls-section">
        <div class="mgg-search-bar">
            <input type="text" 
                   id="mgg-search-input" 
                   placeholder="Search terms..." 
                   value="<?php echo esc_attr($initial_search); ?>"
                   class="mgg-search-field">
            <button id="mgg-search-btn" class="mgg-search-button">
                <span class="mgg-search-icon">🔍</span>
            </button>
        </div>
        
        <div class="mgg-filters">
            <div class="mgg-filter-group">
                <label for="mgg-category-filter">Category:</label>
                <select id="mgg-category-filter" class="mgg-filter-select">
                    <option value="">All Categories</option>
                    <?php foreach ($categories as $category): ?>
                        <option value="<?php echo esc_attr($category['slug']); ?>" 
                                <?php selected($initial_category, $category['slug']); ?>>
                            <?php echo esc_html($category['name']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            
            <div class="mgg-filter-group">
                <label for="mgg-difficulty-filter">Difficulty:</label>
                <select id="mgg-difficulty-filter" class="mgg-filter-select">
                    <option value="">All Levels</option>
                    <option value="tourist" <?php selected($initial_difficulty, 'tourist'); ?>>Tourist</option>
                    <option value="local" <?php selected($initial_difficulty, 'local'); ?>>Local</option>
                    <option value="expert" <?php selected($initial_difficulty, 'expert'); ?>>Expert</option>
                </select>
            </div>
            
            <div class="mgg-filter-group">
                <label for="mgg-sort-filter">Sort by:</label>
                <select id="mgg-sort-filter" class="mgg-filter-select">
                    <option value="term" <?php selected($initial_sort, 'term'); ?>>A-Z</option>
                    <option value="category" <?php selected($initial_sort, 'category'); ?>>Category</option>
                    <option value="difficulty" <?php selected($initial_sort, 'difficulty'); ?>>Difficulty</option>
                    <option value="views" <?php selected($initial_sort, 'views'); ?>>Most Popular</option>
                </select>
            </div>
        </div>
        
        <!-- View Toggle -->
        <div class="mgg-view-controls">
            <button id="mgg-grid-view" class="mgg-view-btn mgg-view-active" data-view="grid">
                <span class="mgg-grid-icon">⊞</span> Grid
            </button>
            <button id="mgg-list-view" class="mgg-view-btn" data-view="list">
                <span class="mgg-list-icon">☰</span> List
            </button>
        </div>
    </div>
    
    <!-- Results Info -->
    <div class="mgg-results-info">
        <span id="mgg-results-count">
            Showing <strong id="mgg-count-current"><?php echo count($terms); ?></strong> 
            of <strong id="mgg-count-total"><?php echo $total_count; ?></strong> terms
        </span>
        
        <div class="mgg-loading" id="mgg-loading" style="display: none;">
            <span class="mgg-spinner">⟳</span> Loading...
        </div>
    </div>
    
    <!-- Terms Display -->
    <div id="mgg-terms-container" class="mgg-terms-grid">
        <?php if (!empty($terms)): ?>
            <?php foreach ($terms as $term): ?>
                <?php include MGG_PLUGIN_PATH . 'templates/partials/term-card.php'; ?>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="mgg-no-results">
                <h3>No terms found</h3>
                <p>Try adjusting your search or filters to find what you're looking for.</p>
            </div>
        <?php endif; ?>
    </div>
    
    <!-- Load More Button -->
    <div class="mgg-load-more-container" id="mgg-load-more-container" style="<?php echo count($terms) < $total_count ? '' : 'display: none;'; ?>">
        <button id="mgg-load-more" class="mgg-load-more-btn">
            Load More Terms
        </button>
    </div>
    
</div>

<!-- SEO Schema Markup -->
<script type="application/ld+json">
{
    "@context": "https://schema.org",
    "@type": "WebSite",
    "name": "Mardi Gras Glossary",
    "description": "Complete guide to Mardi Gras and Carnival terminology",
    "url": "<?php echo home_url('/mardi-gras-glossary/'); ?>",
    "potentialAction": {
        "@type": "SearchAction",
        "target": "<?php echo home_url('/mardi-gras-glossary/'); ?>?search={search_term}",
        "query-input": "required name=search_term"
    }
}
</script>
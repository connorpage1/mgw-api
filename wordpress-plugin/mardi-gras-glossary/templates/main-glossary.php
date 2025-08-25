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

// Fetch initial terms (get all terms)
$params = array();
if ($initial_search) $params['search'] = $initial_search;
if ($initial_category) $params['category'] = $initial_category;
if ($initial_difficulty) $params['difficulty'] = $initial_difficulty;
if ($initial_sort) $params['sort'] = $initial_sort;

$terms_data = $glossary->fetch_terms($params);
$terms = $terms_data['terms'] ?? array();
$total_count = $terms_data['count'] ?? 0;


// Get display options (for Elementor widget support)
$show_search = !isset($atts['show_search']) || $atts['show_search'] !== 'no';
$show_filters = !isset($atts['show_filters']) || $atts['show_filters'] !== 'no';
$show_stats = !isset($atts['show_stats']) || $atts['show_stats'] !== 'no';
$show_hero = !isset($atts['show_hero']) || $atts['show_hero'] !== 'no';
?>

<div class="mgg-main-glossary">
    <div class="mgg-spacer" style="height: 60px;"></div>
    
    <!-- Hero Section with Inspiro Styling -->
    <?php if ($show_hero): ?>
    <div class="mgg-hero-section">
        <div class="mgg-hero-content">
            <h1 class="mgg-main-title">Complete Mardi Gras Glossary</h1>
            <p class="mgg-hero-subtitle">Your comprehensive guide to Carnival and Mardi Gras terminology, traditions, and culture</p>
        </div>
    </div>
    <?php else: ?>
    <div class="mgg-page-header">
        <h1 class="mgg-simple-title">Mardi Gras Glossary</h1>
    </div>
    <?php endif; ?>
    
    <!-- Main Content Container -->
    <div class="mgg-main-content">
        
        <!-- Sidebar with Filters -->
        <aside class="mgg-sidebar">
            <div class="mgg-sidebar-section">
                <h3 class="mgg-sidebar-title">Search & Filter</h3>
                
                <!-- Search Bar -->
                <?php if ($show_search): ?>
                <div class="mgg-search-container">
                    <input type="text" 
                           id="mgg-search-input" 
                           placeholder="Search terms..." 
                           value="<?php echo esc_attr($initial_search); ?>"
                           class="mgg-search-field">
                    <button id="mgg-search-btn" class="mgg-search-btn">
                        <span class="material-icons">search</span>
                    </button>
                </div>
                <?php endif; ?>
                
                <!-- Filter Controls -->
                <?php if ($show_filters): ?>
                <div class="mgg-filters">
                    <div class="mgg-filter-item">
                        <label for="mgg-category-filter" class="mgg-filter-label">Category</label>
                        <select id="mgg-category-filter" class="mgg-filter-select">
                            <option value="">All Categories</option>
                            <?php if (empty($categories)): ?>
                                <!-- DEBUG: No categories found -->
                                <option disabled>No categories available</option>
                            <?php else: ?>
                                <?php foreach ($categories as $category): ?>
                                    <option value="<?php echo esc_attr($category['slug']); ?>" 
                                            <?php selected($initial_category, $category['slug']); ?>>
                                        <?php echo esc_html($category['name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </select>
                    </div>
                    
                    <div class="mgg-filter-item">
                        <label for="mgg-difficulty-filter" class="mgg-filter-label">Difficulty Level</label>
                        <select id="mgg-difficulty-filter" class="mgg-filter-select">
                            <option value="">All Levels</option>
                            <option value="tourist" <?php selected($initial_difficulty, 'tourist'); ?>>Tourist</option>
                            <option value="local" <?php selected($initial_difficulty, 'local'); ?>>Local</option>
                            <option value="expert" <?php selected($initial_difficulty, 'expert'); ?>>Expert</option>
                        </select>
                    </div>
                    
                    <div class="mgg-filter-item">
                        <label for="mgg-sort-filter" class="mgg-filter-label">Sort By</label>
                        <select id="mgg-sort-filter" class="mgg-filter-select">
                            <option value="term" <?php selected($initial_sort, 'term'); ?>>Alphabetical</option>
                            <option value="category" <?php selected($initial_sort, 'category'); ?>>Category</option>
                            <option value="difficulty" <?php selected($initial_sort, 'difficulty'); ?>>Difficulty</option>
                            <option value="views" <?php selected($initial_sort, 'views'); ?>>Most Popular</option>
                        </select>
                    </div>
                </div>
                
                <!-- Clear Filters Button -->
                <button id="mgg-clear-filters" class="mgg-clear-btn">Clear All Filters</button>
                <?php endif; ?>
            </div>
            
            <!-- Quick Stats -->
            <?php if ($show_stats): ?>
            <div class="mgg-sidebar-section">
                <h3 class="mgg-sidebar-title">Quick Stats</h3>
                <div class="mgg-stats-list">
                    <div class="mgg-stat-item">
                        <span class="mgg-stat-number"><?php echo $total_count; ?></span>
                        <span class="mgg-stat-label">Total Terms</span>
                    </div>
                    <div class="mgg-stat-item">
                        <span class="mgg-stat-number"><?php echo count($categories); ?></span>
                        <span class="mgg-stat-label">Categories</span>
                    </div>
                </div>
            </div>
            <?php endif; ?>
            
            <!-- Categories List -->
            <div class="mgg-sidebar-section">
                <h3 class="mgg-sidebar-title">Browse by Category</h3>
                <ul class="mgg-category-list">
                    <?php foreach ($categories as $category): ?>
                        <li class="mgg-category-item">
                            <a href="<?php echo home_url('/mardi-gras/glossary/category/' . $category['slug'] . '/'); ?>" 
                               class="mgg-category-link">
                                <span class="mgg-category-name"><?php echo esc_html($category['name']); ?></span>
                                <span class="mgg-category-count"><?php echo $category['term_count']; ?></span>
                            </a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </aside>
        
        <!-- Main Content Area -->
        <main class="mgg-content">
            
            <!-- Results Header -->
            <div class="mgg-results-header">
                <div class="mgg-results-info">
                    <span id="mgg-results-count">
                        Showing <strong id="mgg-count-current"><?php echo count($terms); ?></strong> 
                        of <strong id="mgg-count-total"><?php echo $total_count; ?></strong> terms
                    </span>
                </div>
            </div>
            
            <!-- Controls Row -->
            <div class="mgg-controls-row">
                <div class="mgg-inline-filters">
                    <div class="mgg-filter-item">
                        <label for="mgg-difficulty-filter-inline" class="mgg-filter-label">Difficulty:</label>
                        <select id="mgg-difficulty-filter-inline" class="mgg-filter-select">
                            <option value="">All Levels</option>
                            <option value="tourist" <?php selected($initial_difficulty, 'tourist'); ?>>Tourist</option>
                            <option value="local" <?php selected($initial_difficulty, 'local'); ?>>Local</option>
                            <option value="expert" <?php selected($initial_difficulty, 'expert'); ?>>Expert</option>
                        </select>
                    </div>
                    
                    <div class="mgg-filter-item">
                        <label for="mgg-sort-filter-inline" class="mgg-filter-label">Sort by:</label>
                        <select id="mgg-sort-filter-inline" class="mgg-filter-select">
                            <option value="term" <?php selected($initial_sort, 'term'); ?>>Alphabetical</option>
                            <option value="category" <?php selected($initial_sort, 'category'); ?>>Category</option>
                            <option value="difficulty" <?php selected($initial_sort, 'difficulty'); ?>>Difficulty</option>
                            <option value="views" <?php selected($initial_sort, 'views'); ?>>Most Popular</option>
                        </select>
                    </div>
                </div>
                
                <div class="mgg-view-controls">
                    <button id="mgg-grid-view" class="mgg-view-btn mgg-view-active" data-view="grid" title="Grid View">
                        <span class="material-icons">grid_view</span>
                        <span class="mgg-view-text">Grid</span>
                    </button>
                    <button id="mgg-list-view" class="mgg-view-btn" data-view="list" title="List View">
                        <span class="material-icons">view_list</span>
                        <span class="mgg-view-text">List</span>
                    </button>
                </div>
            </div>
            
            <!-- Loading Indicator -->
            <div class="mgg-loading" id="mgg-loading" style="display: none;">
                <div class="mgg-loading-content">
                    <span class="material-icons mgg-spinner">refresh</span>
                    <span class="mgg-loading-text">Loading terms...</span>
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
                        <div class="mgg-no-results-content">
                            <h3>No terms found</h3>
                            <p>Try adjusting your search or filters to find what you're looking for.</p>
                            <button onclick="clearAllFilters()" class="mgg-clear-btn">Clear All Filters</button>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
            
            <!-- Load More Button -->
            <div class="mgg-load-more-container" id="mgg-load-more-container" style="<?php echo count($terms) < $total_count ? '' : 'display: none;'; ?>">
                <button id="mgg-load-more" class="mgg-load-more-btn">
                    Load More Terms
                    <span class="mgg-load-more-count">(<span id="mgg-remaining-count"><?php echo max(0, $total_count - count($terms)); ?></span> remaining)</span>
                </button>
            </div>
            
        </main>
        
    </div>
    
</div>

<!-- SEO Schema Markup -->
<script type="application/ld+json">
{
    "@context": "https://schema.org",
    "@type": "WebSite",
    "name": "Mardi Gras Glossary",
    "description": "Complete guide to Mardi Gras and Carnival terminology",
    "url": "<?php echo home_url('/mardi-gras/glossary/'); ?>",
    "potentialAction": {
        "@type": "SearchAction",
        "target": "<?php echo home_url('/mardi-gras/glossary/'); ?>?search={search_term}",
        "query-input": "required name=search_term"
    }
}
</script>
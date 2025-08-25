<?php
/**
 * Category Page Template
 * Displays terms filtered by a specific category
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

$glossary = new MardiGrasGlossary();
$categories_data = $glossary->fetch_categories();
$categories = $categories_data['categories'] ?? array();

// Find the current category - try both slug and name matching
$current_category = null;
foreach ($categories as $cat) {
    if ($cat['slug'] === $category || sanitize_title($cat['name']) === $category) {
        $current_category = $cat;
        break;
    }
}

// If still not found, create a fallback category
if (!$current_category) {
    // Try to get terms for this category anyway
    $terms_data = $glossary->fetch_terms(array('category' => $category, 'limit' => 100));
    $terms = $terms_data['terms'] ?? array();
    
    if (!empty($terms)) {
        // Create a fallback category from the first term
        $current_category = array(
            'name' => $terms[0]['category'] ?? ucwords(str_replace('-', ' ', $category)),
            'slug' => $category,
            'description' => 'Terms in this category'
        );
    } else {
        // 404 - Category not found and no terms
        global $wp_query;
        $wp_query->set_404();
        status_header(404);
        include get_404_template();
        return;
    }
} else {
    // Get terms for this category
    $terms_data = $glossary->fetch_terms(array('category' => $category, 'limit' => 100));
    $terms = $terms_data['terms'] ?? array();
}

$total_count = count($terms);

// Build breadcrumbs
$glossary_url = home_url('/mardi-gras/glossary/');
?>

<div class="mgg-category-page">
    
    <!-- Breadcrumbs -->
    <nav class="mgg-breadcrumbs" aria-label="Breadcrumb">
        <ol class="mgg-breadcrumb-list">
            <li><a href="<?php echo home_url(); ?>">Home</a></li>
            <li><a href="<?php echo home_url('/mardi-gras/'); ?>">Mardi Gras</a></li>
            <li><a href="<?php echo esc_url($glossary_url); ?>">Glossary</a></li>
            <li class="mgg-current"><?php echo esc_html($current_category['name']); ?></li>
        </ol>
    </nav>
    
    <!-- Category Header -->
    <div class="mgg-category-header">
        <div class="mgg-category-hero">
            <h1 class="mgg-category-title"><?php echo esc_html($current_category['name']); ?> Terms</h1>
            <?php if (!empty($current_category['description'])): ?>
                <p class="mgg-category-description"><?php echo esc_html($current_category['description']); ?></p>
            <?php endif; ?>
            <div class="mgg-category-meta">
                <span class="mgg-term-count"><?php echo $total_count; ?> terms in this category</span>
            </div>
        </div>
        
        <!-- Back to main glossary -->
        <div class="mgg-category-navigation">
            <a href="<?php echo esc_url($glossary_url); ?>" class="mgg-back-btn">
                ← Back to All Terms
            </a>
        </div>
    </div>
    
    <!-- Category Controls -->
    <div class="mgg-category-controls">
        <div class="mgg-search-bar">
            <input type="text" 
                   id="mgg-category-search" 
                   placeholder="Search within <?php echo esc_attr($current_category['name']); ?>..." 
                   class="mgg-search-field">
            <button id="mgg-category-search-btn" class="mgg-search-button">
                <span class="mgg-search-icon"></span>
            </button>
        </div>
        
        <div class="mgg-category-filters">
            <div class="mgg-filter-group">
                <label for="mgg-category-difficulty">Difficulty:</label>
                <select id="mgg-category-difficulty" class="mgg-filter-select">
                    <option value="">All Levels</option>
                    <option value="tourist">Tourist</option>
                    <option value="local">Local</option>
                    <option value="expert">Expert</option>
                </select>
            </div>
            
            <div class="mgg-filter-group">
                <label for="mgg-category-sort">Sort by:</label>
                <select id="mgg-category-sort" class="mgg-filter-select">
                    <option value="term">A-Z</option>
                    <option value="difficulty">Difficulty</option>
                    <option value="views">Most Popular</option>
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
    
    <!-- Terms Display -->
    <div id="mgg-category-terms" class="mgg-terms-grid">
        <?php if (!empty($terms)): ?>
            <?php foreach ($terms as $term): ?>
                <?php include MGG_PLUGIN_PATH . 'templates/partials/term-card.php'; ?>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="mgg-no-results">
                <h3>No terms found in this category</h3>
                <p>This category doesn't have any terms yet, or they may be temporarily unavailable.</p>
                <a href="<?php echo esc_url($glossary_url); ?>" class="mgg-browse-all">Browse All Terms</a>
            </div>
        <?php endif; ?>
    </div>
    
    <!-- Category Footer -->
    <div class="mgg-category-footer">
        <div class="mgg-category-stats">
            <h3>Category Statistics</h3>
            <div class="mgg-stats-grid">
                <div class="mgg-stat-box">
                    <span class="mgg-stat-number"><?php echo $total_count; ?></span>
                    <span class="mgg-stat-label">Total Terms</span>
                </div>
                <?php
                // Calculate difficulty breakdown
                $difficulty_counts = array('tourist' => 0, 'local' => 0, 'expert' => 0);
                foreach ($terms as $term) {
                    if (isset($difficulty_counts[$term['difficulty']])) {
                        $difficulty_counts[$term['difficulty']]++;
                    }
                }
                ?>
                <div class="mgg-stat-box">
                    <span class="mgg-stat-number"><?php echo $difficulty_counts['tourist']; ?></span>
                    <span class="mgg-stat-label">Tourist Level</span>
                </div>
                <div class="mgg-stat-box">
                    <span class="mgg-stat-number"><?php echo $difficulty_counts['local']; ?></span>
                    <span class="mgg-stat-label">Local Level</span>
                </div>
                <div class="mgg-stat-box">
                    <span class="mgg-stat-number"><?php echo $difficulty_counts['expert']; ?></span>
                    <span class="mgg-stat-label">Expert Level</span>
                </div>
            </div>
        </div>
        
        <!-- Related Categories -->
        <?php if (count($categories) > 1): ?>
            <div class="mgg-related-categories">
                <h3>Explore Other Categories</h3>
                <div class="mgg-category-links">
                    <?php foreach ($categories as $cat): ?>
                        <?php if ($cat['slug'] !== $category): ?>
                            <a href="<?php echo home_url('/mardi-gras/glossary/category/' . $cat['slug'] . '/'); ?>" 
                               class="mgg-category-link">
                                <span class="mgg-category-name"><?php echo esc_html($cat['name']); ?></span>
                                <span class="mgg-category-count"><?php echo $cat['term_count']; ?> terms</span>
                            </a>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>
    </div>
    
</div>

<!-- Category-specific JavaScript -->
<script>
jQuery(document).ready(function($) {
    const categorySlug = '<?php echo esc_js($category); ?>';
    let filteredTerms = <?php echo json_encode($terms); ?>;
    
    // Search within category
    let searchTimeout;
    $('#mgg-category-search').on('input', function() {
        clearTimeout(searchTimeout);
        const searchTerm = $(this).val().toLowerCase();
        
        searchTimeout = setTimeout(function() {
            filterCategoryTerms(searchTerm, $('#mgg-category-difficulty').val(), $('#mgg-category-sort').val());
        }, 300);
    });
    
    // Filter by difficulty
    $('#mgg-category-difficulty').on('change', function() {
        const difficulty = $(this).val();
        const search = $('#mgg-category-search').val().toLowerCase();
        const sort = $('#mgg-category-sort').val();
        filterCategoryTerms(search, difficulty, sort);
    });
    
    // Sort terms
    $('#mgg-category-sort').on('change', function() {
        const sort = $(this).val();
        const search = $('#mgg-category-search').val().toLowerCase();
        const difficulty = $('#mgg-category-difficulty').val();
        filterCategoryTerms(search, difficulty, sort);
    });
    
    // View toggle
    $('.mgg-view-btn').on('click', function() {
        const viewType = $(this).data('view');
        
        $('.mgg-view-btn').removeClass('mgg-view-active');
        $(this).addClass('mgg-view-active');
        
        const container = $('#mgg-category-terms');
        container.removeClass('mgg-terms-grid mgg-terms-list');
        container.addClass('mgg-terms-' + viewType);
    });
    
    function filterCategoryTerms(search, difficulty, sort) {
        let filtered = [...<?php echo json_encode($terms); ?>];
        
        // Apply search filter
        if (search) {
            filtered = filtered.filter(term => 
                term.term.toLowerCase().includes(search) ||
                term.definition.toLowerCase().includes(search) ||
                term.pronunciation.toLowerCase().includes(search)
            );
        }
        
        // Apply difficulty filter
        if (difficulty) {
            filtered = filtered.filter(term => term.difficulty === difficulty);
        }
        
        // Apply sorting
        filtered.sort((a, b) => {
            switch(sort) {
                case 'difficulty':
                    const difficultyOrder = {'tourist': 1, 'local': 2, 'expert': 3};
                    return difficultyOrder[a.difficulty] - difficultyOrder[b.difficulty];
                case 'views':
                    return b.view_count - a.view_count;
                case 'term':
                default:
                    return a.term.localeCompare(b.term);
            }
        });
        
        // Update display
        displayCategoryTerms(filtered);
    }
    
    function displayCategoryTerms(terms) {
        const container = $('#mgg-category-terms');
        
        if (terms.length === 0) {
            container.html(`
                <div class="mgg-no-results">
                    <h3>No terms match your criteria</h3>
                    <p>Try adjusting your search or filters.</p>
                    <button onclick="clearCategoryFilters()" class="mgg-clear-filters">Clear Filters</button>
                </div>
            `);
            return;
        }
        
        let html = '';
        terms.forEach(term => {
            html += createCategoryTermCard(term);
        });
        
        container.html(html);
    }
    
    function createCategoryTermCard(term) {
        const termUrl = '<?php echo home_url('/mardi-gras/glossary/'); ?>' + term.slug + '/';
        const difficultyClass = 'mgg-difficulty-' + term.difficulty.toLowerCase();
        
        let definition = term.definition;
        if (definition.length > 150) {
            definition = definition.substring(0, 150) + '...';
        }
        
        return `
            <article class="mgg-term-card ${difficultyClass}">
                <header class="mgg-term-header">
                    <h3 class="mgg-term-title">
                        <a href="${termUrl}" class="mgg-term-link">${term.term}</a>
                    </h3>
                    <div class="mgg-term-meta">
                        <span class="mgg-term-pronunciation">${term.pronunciation}</span>
                        <div class="mgg-term-badges">
                            <span class="mgg-difficulty-badge mgg-difficulty-${term.difficulty.toLowerCase()}">
                                ${term.difficulty.charAt(0).toUpperCase() + term.difficulty.slice(1)}
                            </span>
                            ${term.is_featured ? '<span class="mgg-featured-badge">⭐ Featured</span>' : ''}
                        </div>
                    </div>
                </header>
                <div class="mgg-term-content">
                    <div class="mgg-term-definition">${definition}</div>
                </div>
                <footer class="mgg-term-footer">
                    <div class="mgg-term-stats">
                    </div>
                    <a href="${termUrl}" class="mgg-read-more">Learn More →</a>
                </footer>
            </article>
        `;
    }
    
    window.clearCategoryFilters = function() {
        $('#mgg-category-search').val('');
        $('#mgg-category-difficulty').val('');
        $('#mgg-category-sort').val('term');
        filterCategoryTerms('', '', 'term');
    };
});
</script>

<!-- SEO Schema Markup -->
<script type="application/ld+json">
{
    "@context": "https://schema.org",
    "@type": "CollectionPage",
    "name": "<?php echo esc_js($current_category['name']); ?> - Mardi Gras Glossary",
    "description": "<?php echo esc_js($current_category['description'] ?: 'Mardi Gras and Carnival terms in the ' . $current_category['name'] . ' category'); ?>",
    "url": "<?php echo get_permalink(); ?>",
    "mainEntity": {
        "@type": "ItemList",
        "name": "<?php echo esc_js($current_category['name']); ?> Terms",
        "numberOfItems": <?php echo $total_count; ?>,
        "itemListElement": [
            <?php foreach (array_slice($terms, 0, 10) as $index => $term): ?>
            {
                "@type": "ListItem",
                "position": <?php echo $index + 1; ?>,
                "item": {
                    "@type": "DefinedTerm",
                    "name": "<?php echo esc_js($term['term']); ?>",
                    "description": "<?php echo esc_js(wp_trim_words($term['definition'], 20)); ?>",
                    "url": "<?php echo home_url('/mardi-gras-glossary/' . $term['slug'] . '/'); ?>"
                }
            }<?php echo $index < min(9, count($terms) - 1) ? ',' : ''; ?>
            <?php endforeach; ?>
        ]
    }
}
</script>

<?php
// Update page title and meta description for SEO
add_filter('wp_title', function($title) use ($current_category) {
    return $current_category['name'] . ' Terms - Mardi Gras Glossary | ' . get_bloginfo('name');
});

add_action('wp_head', function() use ($current_category, $total_count) {
    $description = $current_category['description'] ?: 'Explore ' . $total_count . ' Mardi Gras and Carnival terms in the ' . $current_category['name'] . ' category.';
    $description = wp_trim_words($description, 30);
    
    echo '<meta name="description" content="' . esc_attr($description) . '">' . "\n";
    echo '<meta property="og:title" content="' . esc_attr($current_category['name'] . ' Terms - Mardi Gras Glossary') . '">' . "\n";
    echo '<meta property="og:description" content="' . esc_attr($description) . '">' . "\n";
    echo '<meta property="og:url" content="' . get_permalink() . '">' . "\n";
});
?>
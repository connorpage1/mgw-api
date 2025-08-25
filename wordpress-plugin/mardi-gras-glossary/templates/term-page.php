<?php
/**
 * Individual Term Page Template
 * Displays detailed information for a single glossary term
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

$glossary = new MardiGrasGlossary();
$term = $glossary->fetch_term($term_slug);

if (!$term) {
    // 404 - Term not found
    global $wp_query;
    $wp_query->set_404();
    status_header(404);
    include get_404_template();
    return;
}

// Get related terms and categories for navigation
$categories_data = $glossary->fetch_categories();
$categories = $categories_data['categories'] ?? array();

// Get the glossary referrer URL for back navigation
$referrer = wp_get_referer();
$back_url = (strpos($referrer, '/mardi-gras/glossary') !== false) ? $referrer : home_url('/mardi-gras/glossary/');

// Build breadcrumbs
$category_url = home_url('/mardi-gras/glossary/category/' . $term['category_slug'] . '/');
?>

<div class="mgg-term-page">
    
    <!-- Breadcrumbs -->
    <nav class="mgg-breadcrumbs" aria-label="Breadcrumb">
        <ol class="mgg-breadcrumb-list">
            <li><a href="<?php echo home_url(); ?>">Home</a></li>
            <li><a href="<?php echo home_url('/mardi-gras/'); ?>">Mardi Gras</a></li>
            <li><a href="<?php echo home_url('/mardi-gras/glossary/'); ?>">Glossary</a></li>
            <li><a href="<?php echo esc_url($category_url); ?>"><?php echo esc_html($term['category']); ?></a></li>
            <li class="mgg-current"><?php echo esc_html($term['term']); ?></li>
        </ol>
    </nav>
    
    <!-- Back to Glossary Button -->
    <div class="mgg-navigation-top">
        <a href="<?php echo esc_url($back_url); ?>" class="mgg-back-btn">
            ← Back to Glossary
        </a>
        
        <div class="mgg-share-buttons">
            <span>Share:</span>
            <a href="https://twitter.com/intent/tweet?text=<?php echo urlencode($term['term'] . ' - ' . $term['definition']); ?>&url=<?php echo urlencode(get_permalink()); ?>" 
               target="_blank" class="mgg-share-twitter">Twitter</a>
            <a href="https://www.facebook.com/sharer/sharer.php?u=<?php echo urlencode(get_permalink()); ?>" 
               target="_blank" class="mgg-share-facebook">Facebook</a>
        </div>
    </div>
    
    <main class="mgg-term-content">
        
        <!-- Term Header -->
        <header class="mgg-term-header">
            <h1 class="mgg-term-title"><?php echo esc_html($term['term']); ?></h1>
            
            <div class="mgg-term-meta">
                <div class="mgg-pronunciation">
                    <strong>Pronunciation:</strong> 
                    <span class="mgg-phonetic"><?php echo esc_html($term['pronunciation']); ?></span>
                </div>
                
                <div class="mgg-term-badges">
                    <a href="<?php echo esc_url($category_url); ?>" class="mgg-category-badge">
                        <?php echo esc_html($term['category']); ?>
                    </a>
                    <span class="mgg-difficulty-badge mgg-difficulty-<?php echo esc_attr(strtolower($term['difficulty'])); ?>">
                        <?php echo esc_html(ucfirst($term['difficulty']) . ' Level'); ?>
                    </span>
                    <?php if ($term['is_featured']): ?>
                        <span class="mgg-featured-badge">
                            ⭐ Featured Term
                        </span>
                    <?php endif; ?>
                </div>
            </div>
        </header>
        
        <!-- Main Content -->
        <div class="mgg-term-body">
            
            <!-- Definition -->
            <section class="mgg-definition-section">
                <h2>Definition</h2>
                <div class="mgg-definition-text">
                    <?php echo wp_kses_post(nl2br($term['definition'])); ?>
                </div>
            </section>
            
            <!-- Etymology (if available) -->
            <?php if (!empty($term['etymology'])): ?>
                <section class="mgg-etymology-section">
                    <h2>Etymology</h2>
                    <div class="mgg-etymology-text">
                        <?php echo wp_kses_post(nl2br($term['etymology'])); ?>
                    </div>
                </section>
            <?php endif; ?>
            
            <!-- Example (if available) -->
            <?php if (!empty($term['example'])): ?>
                <section class="mgg-example-section">
                    <h2>Example</h2>
                    <div class="mgg-example-text">
                        <?php echo wp_kses_post(nl2br($term['example'])); ?>
                    </div>
                </section>
            <?php endif; ?>
            
        </div>
        
        <!-- Term Stats -->
        <div class="mgg-term-stats">
            <div class="mgg-stat-item">
                <span class="mgg-stat-label">Views:</span>
                <span class="mgg-stat-value"><?php echo number_format($term['view_count']); ?></span>
            </div>
            <div class="mgg-stat-item">
                <span class="mgg-stat-label">Added:</span>
                <span class="mgg-stat-value"><?php echo date('M j, Y', strtotime($term['created_at'])); ?></span>
            </div>
            <div class="mgg-stat-item">
                <span class="mgg-stat-label">Updated:</span>
                <span class="mgg-stat-value"><?php echo date('M j, Y', strtotime($term['updated_at'])); ?></span>
            </div>
        </div>
        
    </main>
    
    <!-- Sidebar with Related Terms -->
    <aside class="mgg-term-sidebar">
        
        <!-- Related Terms -->
        <?php if (!empty($term['related_terms'])): ?>
            <section class="mgg-related-terms">
                <h3>Related Terms</h3>
                <ul class="mgg-related-list">
                    <?php foreach ($term['related_terms'] as $related): ?>
                        <li>
                            <a href="<?php echo home_url('/mardi-gras/glossary/' . $related['slug'] . '/'); ?>">
                                <?php echo esc_html($related['term']); ?>
                            </a>
                            <span class="mgg-related-category"><?php echo esc_html($related['category']); ?></span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </section>
        <?php endif; ?>
        
        <!-- Explore More in Category -->
        <section class="mgg-category-explore">
            <h3>More <?php echo esc_html($term['category']); ?> Terms</h3>
            <a href="<?php echo esc_url($category_url); ?>" class="mgg-explore-btn">
                Explore All <?php echo esc_html($term['category']); ?> Terms →
            </a>
        </section>
        
        <!-- Quick Navigation -->
        <section class="mgg-quick-nav">
            <h3>Quick Navigation</h3>
            <ul class="mgg-nav-list">
                <li><a href="<?php echo home_url('/mardi-gras/glossary/'); ?>">All Terms</a></li>
                <?php foreach ($categories as $cat): ?>
                    <li>
                        <a href="<?php echo home_url('/mardi-gras/glossary/category/' . $cat['slug'] . '/'); ?>">
                            <?php echo esc_html($cat['name']); ?> (<?php echo $cat['term_count']; ?>)
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </section>
        
    </aside>
    
    <!-- Bottom Navigation -->
    <nav class="mgg-term-navigation">
        <a href="<?php echo esc_url($back_url); ?>" class="mgg-nav-back">
            ← Back to Glossary
        </a>
        
        <div class="mgg-nav-actions">
            <a href="<?php echo home_url('/mardi-gras/glossary/'); ?>?search=<?php echo urlencode($term['term']); ?>" class="mgg-search-similar">
                Search Similar Terms
            </a>
        </div>
    </nav>
    
</div>

<!-- SEO Schema Markup -->
<script type="application/ld+json">
{
    "@context": "https://schema.org",
    "@type": "DefinedTerm",
    "name": "<?php echo esc_js($term['term']); ?>",
    "description": "<?php echo esc_js(strip_tags($term['definition'])); ?>",
    "inDefinedTermSet": {
        "@type": "DefinedTermSet",
        "name": "Mardi Gras Glossary",
        "description": "Complete guide to Mardi Gras and Carnival terminology"
    },
    "termCode": "<?php echo esc_js($term['slug']); ?>",
    "url": "<?php echo get_permalink(); ?>"
}
</script>

<?php
// Update page title and meta description for SEO
add_filter('wp_title', function($title) use ($term) {
    return $term['term'] . ' - Mardi Gras Glossary | ' . get_bloginfo('name');
});

add_action('wp_head', function() use ($term) {
    $description = wp_trim_words(strip_tags($term['definition']), 30);
    echo '<meta name="description" content="' . esc_attr($description) . '">' . "\n";
    echo '<meta property="og:title" content="' . esc_attr($term['term'] . ' - Mardi Gras Glossary') . '">' . "\n";
    echo '<meta property="og:description" content="' . esc_attr($description) . '">' . "\n";
    echo '<meta property="og:url" content="' . get_permalink() . '">' . "\n";
});
?>
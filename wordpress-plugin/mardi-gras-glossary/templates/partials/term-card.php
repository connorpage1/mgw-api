<?php
/**
 * Term Card Partial
 * Displays individual term cards in both grid and list views
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

$term_url = home_url('/mardi-gras/glossary/' . $term['slug'] . '/');
$difficulty_class = 'mgg-difficulty-' . strtolower($term['difficulty']);

// Handle category URL - make sure category_slug exists
$category_slug = !empty($term['category_slug']) ? $term['category_slug'] : sanitize_title($term['category']);
$category_url = home_url('/mardi-gras/glossary/category/' . $category_slug . '/');
?>

<article class="mgg-term-card <?php echo esc_attr($difficulty_class); ?>" data-term-id="<?php echo esc_attr($term['id']); ?>">
    
    <!-- Term Header -->
    <header class="mgg-term-header">
        <h3 class="mgg-term-title">
            <a href="<?php echo esc_url($term_url); ?>" class="mgg-term-link">
                <?php echo esc_html($term['term']); ?>
            </a>
        </h3>
        
        <div class="mgg-term-meta">
            <span class="mgg-term-pronunciation"><?php echo esc_html($term['pronunciation']); ?></span>
            
            <div class="mgg-term-badges">
                <a href="<?php echo esc_url($category_url); ?>" class="mgg-category-badge">
                    <?php echo esc_html($term['category']); ?>
                </a>
                <span class="mgg-difficulty-badge mgg-difficulty-<?php echo esc_attr(strtolower($term['difficulty'])); ?>">
                    <?php echo esc_html(ucfirst($term['difficulty'])); ?>
                </span>
            </div>
        </div>
    </header>
    
    <!-- Term Content -->
    <div class="mgg-term-content">
        <div class="mgg-term-definition">
            <?php 
            $definition = $term['definition'];
            // Truncate for card view
            if (strlen($definition) > 150) {
                $definition = substr($definition, 0, 150) . '...';
            }
            echo esc_html($definition);
            ?>
        </div>
        
        <?php if (!empty($term['example'])): ?>
            <div class="mgg-term-example">
                <strong>Example:</strong> 
                <?php 
                $example = $term['example'];
                if (strlen($example) > 100) {
                    $example = substr($example, 0, 100) . '...';
                }
                echo esc_html($example);
                ?>
            </div>
        <?php endif; ?>
    </div>
    
    <!-- Term Footer -->
    <footer class="mgg-term-footer">
        <div class="mgg-term-stats">
            
            <?php if ($term['is_featured']): ?>
                <span class="mgg-featured-badge">
                    <span class="mgg-star-icon">⭐</span> Featured
                </span>
            <?php endif; ?>
        </div>
        
        <a href="<?php echo esc_url($term_url); ?>" class="mgg-read-more">
            Learn More →
        </a>
    </footer>
    
</article>
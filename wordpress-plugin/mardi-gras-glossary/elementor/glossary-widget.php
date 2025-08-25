<?php
/**
 * Mardi Gras Glossary Elementor Widget
 * Custom Elementor widget for the glossary
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class MGG_Elementor_Glossary_Widget extends \Elementor\Widget_Base {

    public function get_name() {
        return 'mardi_gras_glossary';
    }

    public function get_title() {
        return __('Mardi Gras Glossary', 'mardi-gras-glossary');
    }

    public function get_icon() {
        return 'eicon-search';
    }

    public function get_categories() {
        return ['mardi-gras'];
    }

    public function get_keywords() {
        return ['mardi gras', 'glossary', 'terms', 'dictionary', 'search'];
    }

    protected function _register_controls() {

        // Content Section
        $this->start_controls_section(
            'content_section',
            [
                'label' => __('Content Settings', 'mardi-gras-glossary'),
                'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
            ]
        );

        $this->add_control(
            'view_type',
            [
                'label' => __('Default View', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::SELECT,
                'default' => 'main',
                'options' => [
                    'main' => __('Full Glossary', 'mardi-gras-glossary'),
                    'category' => __('Category Only', 'mardi-gras-glossary'),
                    'search' => __('Search Only', 'mardi-gras-glossary'),
                ],
            ]
        );

        $this->add_control(
            'category_filter',
            [
                'label' => __('Show Category', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::SELECT,
                'default' => '',
                'options' => $this->get_categories_list(),
                'condition' => [
                    'view_type' => 'category',
                ],
            ]
        );

        $this->add_control(
            'terms_limit',
            [
                'label' => __('Terms Limit', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::NUMBER,
                'min' => 5,
                'max' => 100,
                'step' => 5,
                'default' => 50,
            ]
        );

        $this->end_controls_section();

        // Display Options Section
        $this->start_controls_section(
            'display_section',
            [
                'label' => __('Display Options', 'mardi-gras-glossary'),
                'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
            ]
        );

        $this->add_control(
            'show_search',
            [
                'label' => __('Show Search Bar', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::SWITCHER,
                'label_on' => __('Yes', 'mardi-gras-glossary'),
                'label_off' => __('No', 'mardi-gras-glossary'),
                'return_value' => 'yes',
                'default' => 'yes',
            ]
        );

        $this->add_control(
            'show_filters',
            [
                'label' => __('Show Filters', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::SWITCHER,
                'label_on' => __('Yes', 'mardi-gras-glossary'),
                'label_off' => __('No', 'mardi-gras-glossary'),
                'return_value' => 'yes',
                'default' => 'yes',
            ]
        );

        $this->add_control(
            'show_stats',
            [
                'label' => __('Show Statistics', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::SWITCHER,
                'label_on' => __('Yes', 'mardi-gras-glossary'),
                'label_off' => __('No', 'mardi-gras-glossary'),
                'return_value' => 'yes',
                'default' => 'yes',
            ]
        );

        $this->add_control(
            'show_hero',
            [
                'label' => __('Show Hero Section', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::SWITCHER,
                'label_on' => __('Yes', 'mardi-gras-glossary'),
                'label_off' => __('No', 'mardi-gras-glossary'),
                'return_value' => 'yes',
                'default' => 'yes',
            ]
        );

        $this->end_controls_section();

        // Style Section
        $this->start_controls_section(
            'style_section',
            [
                'label' => __('Style', 'mardi-gras-glossary'),
                'tab' => \Elementor\Controls_Manager::TAB_STYLE,
            ]
        );

        $this->add_control(
            'primary_color',
            [
                'label' => __('Primary Color', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::COLOR,
                'default' => '#667eea',
                'selectors' => [
                    '{{WRAPPER}} .mgg-main-glossary' => '--mgg-accent: {{VALUE}}',
                ],
            ]
        );

        $this->add_control(
            'text_color',
            [
                'label' => __('Text Color', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::COLOR,
                'default' => '#2d3748',
                'selectors' => [
                    '{{WRAPPER}} .mgg-main-glossary' => '--mgg-text: {{VALUE}}',
                ],
            ]
        );

        $this->add_control(
            'background_color',
            [
                'label' => __('Background Color', 'mardi-gras-glossary'),
                'type' => \Elementor\Controls_Manager::COLOR,
                'default' => '#ffffff',
                'selectors' => [
                    '{{WRAPPER}} .mgg-main-glossary' => '--mgg-white: {{VALUE}}',
                ],
            ]
        );

        $this->end_controls_section();
    }

    protected function render() {
        $settings = $this->get_settings_for_display();
        
        // Build shortcode attributes
        $shortcode_atts = [
            'view' => $settings['view_type'],
            'limit' => $settings['terms_limit'],
            'show_search' => $settings['show_search'],
            'show_filters' => $settings['show_filters'],
            'show_stats' => $settings['show_stats'],
            'show_hero' => $settings['show_hero']
        ];
        
        if (!empty($settings['category_filter'])) {
            $shortcode_atts['category'] = $settings['category_filter'];
        }
        
        // Add custom CSS class for Elementor styling
        echo '<div class="mgg-elementor-widget">';
        
        // Render the glossary
        global $mardi_gras_glossary;
        if ($mardi_gras_glossary) {
            echo $mardi_gras_glossary->glossary_shortcode($shortcode_atts);
        } else {
            echo do_shortcode('[mardi_gras_glossary ' . $this->build_shortcode_string($shortcode_atts) . ']');
        }
        
        echo '</div>';
    }

    protected function _content_template() {
        ?>
        <div class="mgg-elementor-widget">
            <div class="mgg-elementor-preview">
                <h3>🎭 Mardi Gras Glossary</h3>
                <p>The glossary will be displayed here with your selected settings.</p>
                <div class="mgg-preview-options">
                    <# if ( settings.show_search === 'yes' ) { #>
                        <span class="mgg-option">✓ Search Bar</span>
                    <# } #>
                    <# if ( settings.show_filters === 'yes' ) { #>
                        <span class="mgg-option">✓ Filters</span>
                    <# } #>
                    <# if ( settings.show_stats === 'yes' ) { #>
                        <span class="mgg-option">✓ Statistics</span>
                    <# } #>
                </div>
            </div>
        </div>
        <style>
            .mgg-elementor-preview {
                padding: 20px;
                background: #f8f9fa;
                border-radius: 8px;
                text-align: center;
                border: 2px dashed #667eea;
            }
            .mgg-preview-options {
                margin-top: 10px;
                display: flex;
                justify-content: center;
                gap: 10px;
                flex-wrap: wrap;
            }
            .mgg-option {
                background: #667eea;
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
            }
        </style>
        <?php
    }

    private function get_categories_list() {
        $categories = ['all' => __('All Categories', 'mardi-gras-glossary')];
        
        // Try to get categories from the glossary instance
        try {
            $glossary = new MardiGrasGlossary();
            $categories_data = $glossary->fetch_categories();
            
            if (!empty($categories_data['categories'])) {
                foreach ($categories_data['categories'] as $category) {
                    $categories[$category['slug']] = $category['name'];
                }
            }
        } catch (Exception $e) {
            // Fallback to default categories
            $categories['core-terms'] = 'Core Terms';
            $categories['krewes'] = 'Krewes';
            $categories['food-drink'] = 'Food & Drink';
            $categories['throws'] = 'Throws';
            $categories['parades'] = 'Parades';
        }
        
        return $categories;
    }

    private function build_shortcode_string($atts) {
        $parts = [];
        foreach ($atts as $key => $value) {
            if (!empty($value)) {
                $parts[] = $key . '="' . esc_attr($value) . '"';
            }
        }
        return implode(' ', $parts);
    }
}
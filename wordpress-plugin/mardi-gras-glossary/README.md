# Mardi Gras Glossary WordPress Plugin

A comprehensive WordPress plugin that integrates your Mardi Gras API with WordPress, creating a beautiful, searchable, and SEO-optimized glossary experience. Designed specifically for the Inspiro theme with seamless navigation and mobile responsiveness.

## Features

✨ **Core Features**
- **Searchable Glossary**: Real-time search with debounced input
- **Advanced Filtering**: Filter by category and difficulty level  
- **Multiple Sort Options**: Alphabetical, popularity, difficulty, and more
- **Dual View Modes**: Grid and list views with user preference saving
- **Seamless Navigation**: Smooth transitions between glossary and individual terms

🎨 **Design & UX**
- **Inspiro Theme Integration**: Matches your existing theme styling
- **Responsive Design**: Mobile-first approach with touch-friendly interface
- **Accessibility**: WCAG compliant with keyboard navigation and screen reader support
- **Smooth Animations**: CSS transitions and hover effects

🔍 **SEO Optimized**
- **Individual Term Pages**: Each term gets its own SEO-friendly URL
- **Structured Data**: Schema.org markup for rich snippets
- **Meta Tags**: Automatic meta descriptions and Open Graph tags
- **Breadcrumb Navigation**: Clear site structure for search engines
- **Internal Linking**: Related terms and category cross-linking

⚡ **Performance**
- **Smart Caching**: Configurable API response caching
- **AJAX Loading**: No page refreshes for filtering and searching
- **Lazy Loading**: Load more functionality for large datasets
- **Optimized Assets**: Minified CSS and JavaScript

## Installation

### Method 1: Manual Installation

1. **Download the Plugin**
   ```bash
   # Copy the plugin folder to your WordPress plugins directory
   cp -r mardi-gras-glossary/ /path/to/wordpress/wp-content/plugins/
   ```

2. **Activate the Plugin**
   - Go to your WordPress admin dashboard
   - Navigate to **Plugins > Installed Plugins**
   - Find "Mardi Gras Glossary" and click **Activate**

3. **Configure Settings**
   - Go to **Settings > Mardi Gras Glossary**
   - Enter your API base URL (e.g., `https://your-app.railway.app`)
   - Configure cache duration and sync frequency
   - Click **Save Settings**

### Method 2: Upload via WordPress Admin

1. **Create ZIP File**
   ```bash
   cd wordpress-plugin/
   zip -r mardi-gras-glossary.zip mardi-gras-glossary/
   ```

2. **Upload via Admin**
   - Go to **Plugins > Add New > Upload Plugin**
   - Choose the ZIP file and click **Install Now**
   - Activate the plugin

## Setup & Configuration

### Initial Configuration

1. **API Connection**
   ```
   Settings > Mardi Gras Glossary
   - API Base URL: https://your-mardi-gras-api.railway.app
   - Cache Duration: 3600 seconds (1 hour)
   - Sync Frequency: Hourly
   ```

2. **Permalink Setup** (Important!)
   ```
   Settings > Permalinks > Save Changes
   ```
   This flushes rewrite rules and enables custom URLs.

### Usage Options

#### Option 1: Shortcode (Recommended)
Add the glossary to any page or post:
```
[mardi_gras_glossary]
```

**Shortcode Parameters:**
```
[mardi_gras_glossary view="main" limit="50"]
```

#### Option 2: Direct URLs
The plugin automatically creates these URLs:

- **Main Glossary**: `/mardi-gras/glossary/`
- **Category Pages**: `/mardi-gras/glossary/category/krewes/`
- **Individual Terms**: `/mardi-gras/glossary/king-cake/`
- **Search Results**: `/mardi-gras/glossary/?search=parade`

## Features in Detail

### Main Glossary Page

**Search & Filtering:**
- Real-time search with 300ms debounce
- Category filtering (Core Terms, Krewes, Food & Drink, etc.)
- Difficulty level filtering (Tourist, Local, Expert)
- Multiple sort options (A-Z, Category, Difficulty, Most Popular)

**Display Options:**
- Grid view (default) - Card-based layout
- List view - Compact horizontal layout
- User preference saving in localStorage
- Responsive breakpoints for all devices

### Individual Term Pages

**Content Sections:**
- Complete term definition with pronunciation
- Etymology and historical context (when available)
- Usage examples and context
- Related terms in the same category
- View count and popularity metrics

**Navigation:**
- Breadcrumb navigation
- "Back to Glossary" with filter state preservation
- Category exploration links
- Social sharing buttons

### Category Pages

**Features:**
- Category-specific filtering and search
- Statistical breakdowns by difficulty
- Related category suggestions
- Optimized URLs for SEO

## API Integration

### Required Endpoints
Your Mardi Gras API must provide these endpoints:

```
GET /glossary/terms
- Parameters: search, category, difficulty, limit
- Returns: { terms: [...], count: number }

GET /glossary/term/<slug>
- Returns: { term, pronunciation, definition, ... }

GET /glossary/categories
- Returns: { categories: [...] }

GET /glossary/stats
- Returns: { total_terms, total_categories, ... }
```

### Caching Strategy
- **Terms**: Cached for 1 hour (configurable)
- **Categories**: Cached for 4 hours (less frequent changes)
- **Individual Terms**: Cached for 1 hour
- **Manual Cache Clear**: Available in admin settings

## Customization

### CSS Customization

The plugin uses CSS custom properties for easy theming:

```css
:root {
  --inspiro-accent-color: #6f42c1;
  --inspiro-accent-hover: #5a359a;
  --inspiro-text-color: #333;
  --inspiro-bg-light: #f8f9fa;
}
```

### Styling Classes

Key CSS classes for customization:
```css
.mgg-main-glossary       /* Main container */
.mgg-hero-section        /* Header section */
.mgg-term-card          /* Individual term cards */
.mgg-search-bar         /* Search interface */
.mgg-filters            /* Filter controls */
```

### JavaScript Hooks

Extend functionality with custom JavaScript:
```javascript
// Custom search handler
jQuery(document).on('mgg_search_complete', function(e, results) {
    // Handle search results
});

// Custom filter handler  
jQuery(document).on('mgg_filter_change', function(e, filters) {
    // Handle filter changes
});
```

## SEO Features

### Automatic SEO Optimization

1. **URL Structure**
   - Clean, descriptive URLs
   - Category-based organization
   - No unnecessary parameters

2. **Meta Tags**
   - Auto-generated meta descriptions from term definitions
   - Open Graph tags for social sharing
   - Title optimization with site branding

3. **Structured Data**
   ```json
   {
     "@type": "DefinedTerm",
     "name": "King Cake",
     "description": "Traditional Mardi Gras pastry...",
     "inDefinedTermSet": "Mardi Gras Glossary"
   }
   ```

4. **Internal Linking**
   - Related terms cross-linking
   - Category page connections
   - Breadcrumb navigation

### Search Engine Benefits
- Individual pages for each term (better indexing)
- Rich snippets potential with structured data
- Category-based site architecture
- Mobile-first responsive design
- Fast loading with caching

## Troubleshooting

### Common Issues

**Terms not appearing:**
```
1. Check API URL in Settings > Mardi Gras Glossary
2. Verify API is running and accessible
3. Clear cache in plugin settings
4. Check browser console for JavaScript errors
```

**404 errors on glossary pages:**
```
1. Go to Settings > Permalinks
2. Click "Save Changes" (flushes rewrite rules)
3. Test URLs again
4. Ensure no other plugin conflicts with /mardi-gras/ URLs
```

**Styling issues:**
```
1. Plugin designed for Inspiro theme
2. Add custom CSS for theme compatibility
3. Check for theme CSS conflicts
4. Use browser developer tools to debug
```

**Slow performance:**
```
1. Increase cache duration in settings
2. Check API server response time
3. Consider CDN for static assets
4. Monitor browser network tab
```

### Debug Mode

Enable WordPress debug mode to troubleshoot:
```php
// wp-config.php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
```

Check logs in `/wp-content/debug.log`

## Support & Development

### Plugin Structure
```
mardi-gras-glossary/
├── mardi-gras-glossary.php    # Main plugin file
├── assets/
│   ├── css/glossary.css       # Styles
│   └── js/glossary.js         # JavaScript
├── templates/
│   ├── main-glossary.php      # Main page template
│   ├── term-page.php          # Individual term template
│   ├── category-page.php      # Category template
│   └── partials/
│       └── term-card.php      # Term card component
├── admin/
│   └── settings.php           # Admin settings page
└── README.md                  # This file
```

### Contributing

To contribute to this plugin:

1. **Development Setup**
   ```bash
   git clone <repository>
   cd mardi-gras-glossary
   npm install  # If using build tools
   ```

2. **Testing**
   - Test with WordPress 6.0+
   - Verify Inspiro theme compatibility  
   - Check mobile responsiveness
   - Validate SEO markup

3. **Best Practices**
   - Follow WordPress coding standards
   - Maintain accessibility compliance
   - Test with multiple PHP versions
   - Document all new features

## License

This plugin is licensed under GPL v2 or later.

## Changelog

### Version 1.0.0
- Initial release
- Complete glossary functionality
- Inspiro theme integration
- SEO optimization
- Mobile responsiveness
- Admin configuration panel
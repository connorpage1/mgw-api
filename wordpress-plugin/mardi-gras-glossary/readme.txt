=== Mardi Gras Glossary ===
Contributors: connorpage
Tags: glossary, mardi-gras, carnival, terminology, api
Requires at least: 5.0
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 1.1.7
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A comprehensive Mardi Gras terminology glossary developed exclusively for Mardi Gras World in New Orleans, LA.

== Description ==

The Mardi Gras Glossary plugin creates a beautiful, searchable glossary of Mardi Gras and Carnival terminology. This plugin was developed exclusively for Mardi Gras World in New Orleans, Louisiana, to showcase their comprehensive collection of Mardi Gras knowledge and terminology.

= Key Features =

* **Searchable Interface** - Real-time search with instant results
* **Advanced Filtering** - Filter by category and difficulty level
* **SEO Optimized** - Individual pages for each term with proper meta tags
* **API Integration** - Connects to your existing Mardi Gras API
* **Elementor Widget** - Native Elementor widget with full customization options
* **Responsive Design** - Mobile-first design that works on all devices
* **Inspiro Theme Compatible** - Seamlessly matches the Inspiro theme

= URL Structure =

The plugin creates these clean, SEO-friendly URLs:
* Main Glossary: `/mardi-gras/glossary/`
* Categories: `/mardi-gras/glossary/category/krewes/`
* Individual Terms: `/mardi-gras/glossary/king-cake/`

= Developed For =

* **Mardi Gras World** - New Orleans, Louisiana
* The world's premier Mardi Gras experience and museum
* Home to authentic Mardi Gras float construction
* Preserving and sharing Carnival traditions since 1947

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/mardi-gras-glossary/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to Settings > Mardi Gras Glossary to configure your API
4. Go to Settings > Permalinks and click "Save Changes" to flush rewrite rules
5. Add the glossary to any page using `[mardi_gras_glossary]` or visit `/mardi-gras/glossary/`

== Frequently Asked Questions ==

= Do I need a separate API? =

Yes, this plugin connects to a Mardi Gras terminology API. You'll need to configure the API URL in the plugin settings.

= Can I customize the appearance? =

The plugin is designed to work with the Inspiro theme, but you can customize the appearance using CSS. All elements have CSS classes for easy styling.

= Does this work with Elementor? =

Yes! The plugin includes a native Elementor widget with full customization options including colors, display settings, and content filters.

= Will this work with my theme? =

The plugin is optimized for the Inspiro theme but should work with any properly coded WordPress theme. You may need to add custom CSS for perfect integration.

= Can I use this without the API? =

No, the plugin requires an API connection to function. It fetches all term data from your configured API endpoint.

== Screenshots ==

1. Main glossary page with search and filtering
2. Individual term page with detailed information
3. Category browse page
4. Admin settings panel
5. Mobile responsive design

== Changelog ==

= 1.1.7 =
* Fixed: Hero section now has clean light grey background instead of blue gradient
* Fixed: Hero title color is now dark grey instead of white
* Fixed: Restored difficulty badges (Green/Orange/Red) with proper colors
* Fixed: Updated CSS versioning to force cache refresh
* Debug: Added category dropdown debugging to identify loading issues
* Clean: Removed text shadows and blue styling from hero section

= 1.1.6 =
* AGGRESSIVE FIX: Added !important overrides to force white card backgrounds
* FORCE: Completely removed all view counters with triple override (!important, visibility, opacity)
* FORCE: Large term titles (1.8rem) with heavy weight (700)
* CLEAN: Removed debug logging code for production use
* OVERRIDE: Blue styling completely eliminated with aggressive CSS reset
* GUARANTEE: Cards will be white regardless of theme conflicts

= 1.1.5 =
* Fixed: Cards now truly white/grey with no blue backgrounds
* Fixed: Larger term titles (1.6rem, weight 700) for better readability
* Fixed: Color coding only on difficulty badges (Green/Orange/Red)
* Fixed: API URL defaults properly to api.mardigrasworld.com
* Fixed: Added comprehensive debugging for API issues
* Fixed: Consistent cache clearing and API connection handling
* Improved: Better error logging and troubleshooting support

= 1.1.4 =
* Fixed: Critical PHP syntax error that broke websites
* Fixed: Moved clear_all_cache function inside class structure
* Stable: All UI improvements from 1.1.3 maintained

= 1.1.3 =
* Fixed: Clean white/grey card design with no more color schemes
* Fixed: Removed view counters entirely from all cards
* Fixed: Professional CSS search icon replaces emoji
* Fixed: Better title positioning with increased spacing and z-index
* Fixed: Categories dropdown populated with cache clearing on activation
* Improved: Modern clean UI design with better spacing

= 1.1.2 =
* Fixed: Difficulty sorting now works correctly - AJAX handler was missing sort parameter
* Fixed: Category dropdown now populates correctly with default API URL set to api.mardigrasworld.com
* Fixed: Initial page load now respects sort parameter from URL
* Improved: Better API URL configuration with correct default

= 1.1.1 =
* Fixed: API connection status now shows actual configured URL instead of hardcoded reference
* Fixed: Removed hardcoded 50-term limit - now fetches all terms from API
* Fixed: Admin statistics now displays accurate term count
* Fixed: Category links working properly with fallback category creation
* Fixed: Uniform card styling with consistent accent color
* Fixed: Hero section positioning below site navigation
* Improved: Better error handling and API response processing

= 1.1.0 =
* Fixed: Uniform card colors - removed confusing multi-color scheme
* Fixed: Category link 404 errors
* Fixed: Hero section overlap with site banners
* Fixed: Removed mysterious white overlay elements
* Improved: Cleaner visual design with consistent styling
* Improved: Better mobile responsiveness
* Enhanced: More stable Elementor integration

= 1.0.0 =
* Initial release
* Complete glossary functionality with search and filtering
* Native Elementor widget with customization options
* SEO-optimized individual term pages
* API integration with caching
* Inspiro theme compatibility
* Mobile responsive design
* Admin configuration panel

== Upgrade Notice ==

= 1.1.7 =
Fixes hero title color, restores difficulty badges, adds category debugging. Recommended update.

= 1.1.6 =
AGGRESSIVE OVERRIDES: Forces white cards and removes views with !important declarations. Guaranteed fixes.

= 1.1.5 =
Comprehensive fixes: White cards, larger titles, proper difficulty colors, better API handling. Highly recommended.

= 1.1.4 =
CRITICAL FIX: Resolves PHP syntax error that caused website crashes. Immediate update required.

= 1.1.3 =
Major UI improvements: Clean white cards, no view counters, professional search icons, better title positioning. Recommended.

= 1.1.2 =
Important fixes: Difficulty sorting now works, categories populate in dropdown. Recommended update.

= 1.1.1 =
Critical fixes: Resolves API term limit issues, fixes card colors, category links, and hero positioning. Strongly recommended.

= 1.1.0 =
Major visual and functionality improvements. Fixes card colors, 404 errors, and layout issues. Recommended update.

= 1.0.0 =
Initial release of the Mardi Gras Glossary plugin.

== Additional Info ==

For support, documentation, and updates, visit: https://github.com/your-username/mardi-gras-glossary

= Credits =
Developed exclusively by Connor Page for Mardi Gras World, New Orleans, Louisiana. This plugin serves to preserve and share the rich terminology and traditions of authentic New Orleans Mardi Gras and Carnival celebrations.
/**
 * Mardi Gras Glossary JavaScript
 * Handles search, filtering, and interactive features
 */

(function($) {
    'use strict';
    
    let currentPage = 1;
    let isLoading = false;
    let currentFilters = {
        search: '',
        category: '',
        difficulty: '',
        sort: 'term'
    };
    
    $(document).ready(function() {
        initGlossary();
    });
    
    function initGlossary() {
        // Initialize filters from URL parameters
        initFiltersFromURL();
        
        // Bind event handlers
        bindSearchEvents();
        bindFilterEvents();
        bindViewToggle();
        bindLoadMore();
        
        // Setup AJAX form handling
        setupAjaxSearch();
        
        // Initialize view state
        initViewState();
    }
    
    function initFiltersFromURL() {
        const urlParams = new URLSearchParams(window.location.search);
        
        currentFilters.search = urlParams.get('search') || '';
        currentFilters.category = urlParams.get('category') || '';
        currentFilters.difficulty = urlParams.get('difficulty') || '';
        currentFilters.sort = urlParams.get('sort') || 'term';
        
        // Set form values (including inline controls)
        $('#mgg-search-input').val(currentFilters.search);
        $('#mgg-category-filter').val(currentFilters.category);
        $('#mgg-difficulty-filter, #mgg-difficulty-filter-inline').val(currentFilters.difficulty);
        $('#mgg-sort-filter, #mgg-sort-filter-inline').val(currentFilters.sort);
    }
    
    function bindSearchEvents() {
        // Search input with debounce
        let searchTimeout;
        $('#mgg-search-input').on('input', function() {
            clearTimeout(searchTimeout);
            const searchTerm = $(this).val();
            
            searchTimeout = setTimeout(function() {
                currentFilters.search = searchTerm;
                currentPage = 1;
                performSearch();
            }, 300); // 300ms debounce
        });
        
        // Search button click
        $('#mgg-search-btn').on('click', function(e) {
            e.preventDefault();
            currentFilters.search = $('#mgg-search-input').val();
            currentPage = 1;
            performSearch();
        });
        
        // Enter key in search
        $('#mgg-search-input').on('keypress', function(e) {
            if (e.which === 13) { // Enter key
                e.preventDefault();
                $('#mgg-search-btn').click();
            }
        });
    }
    
    function bindFilterEvents() {
        // Category filter
        $('#mgg-category-filter').on('change', function() {
            currentFilters.category = $(this).val();
            currentPage = 1;
            performSearch();
        });
        
        // Difficulty filters (both sidebar and inline)
        $('#mgg-difficulty-filter, #mgg-difficulty-filter-inline').on('change', function() {
            currentFilters.difficulty = $(this).val();
            // Sync both dropdowns
            $('#mgg-difficulty-filter, #mgg-difficulty-filter-inline').val($(this).val());
            currentPage = 1;
            performSearch();
        });
        
        // Sort filters (both sidebar and inline)
        $('#mgg-sort-filter, #mgg-sort-filter-inline').on('change', function() {
            currentFilters.sort = $(this).val();
            // Sync both dropdowns
            $('#mgg-sort-filter, #mgg-sort-filter-inline').val($(this).val());
            currentPage = 1;
            performSearch();
        });
    }
    
    function bindViewToggle() {
        $('.mgg-view-btn').on('click', function() {
            const viewType = $(this).data('view');
            
            // Update button states
            $('.mgg-view-btn').removeClass('mgg-view-active');
            $(this).addClass('mgg-view-active');
            
            // Update container class
            const container = $('#mgg-terms-container');
            container.removeClass('mgg-terms-grid mgg-terms-list');
            container.addClass('mgg-terms-' + viewType);
            
            // Save preference
            localStorage.setItem('mgg-view-preference', viewType);
        });
    }
    
    function bindLoadMore() {
        $('#mgg-load-more').on('click', function(e) {
            e.preventDefault();
            
            if (!isLoading) {
                currentPage++;
                performSearch(true); // true = append results
            }
        });
    }
    
    function initViewState() {
        // Restore saved view preference
        const savedView = localStorage.getItem('mgg-view-preference') || 'grid';
        $('#mgg-' + savedView + '-view').click();
    }
    
    function performSearch(append = false) {
        if (isLoading) return;
        
        isLoading = true;
        showLoading();
        
        // Update URL without page reload
        updateURL();
        
        const data = {
            action: 'mgg_search_terms',
            nonce: mgg_ajax.nonce,
            search: currentFilters.search,
            category: currentFilters.category,
            difficulty: currentFilters.difficulty,
            sort: currentFilters.sort,
            page: currentPage,
            limit: 0  // 0 means no limit - load all terms
        };
        
        $.ajax({
            url: mgg_ajax.ajax_url,
            method: 'POST',
            data: data,
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    displayResults(response.data, append);
                } else {
                    showError('Failed to load terms. Please try again.');
                }
            },
            error: function(xhr, status, error) {
                console.error('AJAX Error:', error);
                showError('Network error. Please check your connection and try again.');
            },
            complete: function() {
                isLoading = false;
                hideLoading();
            }
        });
    }
    
    function displayResults(data, append = false) {
        const container = $('#mgg-terms-container');
        const terms = data.terms || [];
        const totalCount = data.count || 0;
        
        if (!append) {
            container.empty();
        }
        
        if (terms.length === 0 && !append) {
            container.html(getNoResultsHTML());
            $('#mgg-load-more-container').hide();
        } else {
            // Add new terms
            terms.forEach(function(term) {
                container.append(createTermCard(term));
            });
            
            // Update load more visibility
            const currentTermCount = container.find('.mgg-term-card').length;
            if (currentTermCount < totalCount) {
                $('#mgg-load-more-container').show();
            } else {
                $('#mgg-load-more-container').hide();
            }
        }
        
        // Update results count
        updateResultsCount(container.find('.mgg-term-card').length, totalCount);
        
        // Scroll to results if not appending
        if (!append && currentFilters.search) {
            $('html, body').animate({
                scrollTop: container.offset().top - 100
            }, 300);
        }
    }
    
    function createTermCard(term) {
        const termUrl = mgg_ajax.home_url + '/mardi-gras/glossary/' + term.slug + '/';
        const categoryUrl = mgg_ajax.home_url + '/mardi-gras/glossary/category/' + term.category_slug + '/';
        const difficultyClass = 'mgg-difficulty-' + term.difficulty.toLowerCase();
        
        // Shorter definition for more compact cards
        let definition = term.definition;
        if (definition.length > 120) {
            definition = definition.substring(0, 120) + '...';
        }
        
        // Shorter example text
        let example = '';
        if (term.example && term.example.length > 0) {
            let exampleText = term.example;
            if (exampleText.length > 80) {
                exampleText = exampleText.substring(0, 80) + '...';
            }
            example = `<div class="mgg-term-example"><strong>Example:</strong> ${escapeHtml(exampleText)}</div>`;
        }
        
        const featuredBadge = term.is_featured ? 
            `<span class="mgg-featured-badge">⭐ Featured</span>` : '';
        
        return `
            <article class="mgg-term-card ${difficultyClass}" data-term-id="${term.id}">
                <div class="mgg-card-top">
                    <a href="${categoryUrl}" class="mgg-category-badge">${escapeHtml(term.category)}</a>
                    <span class="mgg-pronunciation-top">${escapeHtml(term.pronunciation)}</span>
                </div>
                <header class="mgg-term-header">
                    <h3 class="mgg-term-title">
                        <a href="${termUrl}" class="mgg-term-link">${escapeHtml(term.term)}</a>
                    </h3>
                </header>
                <div class="mgg-term-content">
                    <div class="mgg-term-definition">${escapeHtml(definition)}</div>
                    ${example}
                </div>
                <div class="mgg-difficulty-section">
                    <span class="mgg-difficulty-label">Difficulty:</span>
                    <span class="mgg-difficulty-badge mgg-difficulty-${term.difficulty.toLowerCase()}">
                        ${term.difficulty.charAt(0).toUpperCase() + term.difficulty.slice(1)}
                    </span>
                    ${featuredBadge}
                </div>
                <footer class="mgg-term-footer">
                    <a href="${termUrl}" class="mgg-read-more">Learn More →</a>
                </footer>
            </article>
        `;
    }
    
    function getNoResultsHTML() {
        let message = 'No terms found';
        let suggestion = 'Try adjusting your search or filters to find what you\'re looking for.';
        
        if (currentFilters.search) {
            message = `No terms found for "${currentFilters.search}"`;
            suggestion = 'Try a different search term or remove some filters.';
        }
        
        return `
            <div class="mgg-no-results">
                <h3>${message}</h3>
                <p>${suggestion}</p>
                <button class="mgg-clear-filters" onclick="clearAllFilters()">Clear All Filters</button>
            </div>
        `;
    }
    
    function updateURL() {
        const params = new URLSearchParams();
        
        if (currentFilters.search) params.set('search', currentFilters.search);
        if (currentFilters.category) params.set('category', currentFilters.category);
        if (currentFilters.difficulty) params.set('difficulty', currentFilters.difficulty);
        if (currentFilters.sort !== 'term') params.set('sort', currentFilters.sort);
        
        const newUrl = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
        window.history.replaceState({}, '', newUrl);
    }
    
    function updateResultsCount(current, total) {
        $('#mgg-count-current').text(formatNumber(current));
        $('#mgg-count-total').text(formatNumber(total));
        
        // Update remaining count for load more button
        const remaining = Math.max(0, total - current);
        $('#mgg-remaining-count').text(formatNumber(remaining));
    }
    
    function showLoading() {
        $('#mgg-loading').show();
        $('#mgg-load-more').prop('disabled', true).text('Loading...');
    }
    
    function hideLoading() {
        $('#mgg-loading').hide();
        $('#mgg-load-more').prop('disabled', false).text('Load More Terms');
    }
    
    function showError(message) {
        const errorHtml = `
            <div class="mgg-error-message">
                <p>${message}</p>
                <button onclick="location.reload()" class="mgg-retry-btn">Retry</button>
            </div>
        `;
        $('#mgg-terms-container').html(errorHtml);
        $('#mgg-load-more-container').hide();
    }
    
    // Utility functions
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    function formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    
    // Clear filters functionality
    $('#mgg-clear-filters').on('click', function() {
        clearAllFilters();
    });
    
    // Global functions
    window.clearAllFilters = function() {
        currentFilters = {
            search: '',
            category: '',
            difficulty: '',
            sort: 'term'
        };
        currentPage = 1;
        
        // Reset form values (including inline controls)
        $('#mgg-search-input').val('');
        $('#mgg-category-filter').val('');
        $('#mgg-difficulty-filter, #mgg-difficulty-filter-inline').val('');
        $('#mgg-sort-filter, #mgg-sort-filter-inline').val('term');
        
        performSearch();
    };
    
    // Setup AJAX search for when used as shortcode
    function setupAjaxSearch() {
        // Add home URL to ajax object if not present
        if (typeof mgg_ajax.home_url === 'undefined') {
            mgg_ajax.home_url = window.location.origin;
        }
    }
    
})(jQuery);
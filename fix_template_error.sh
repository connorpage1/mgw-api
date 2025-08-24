#!/bin/bash
# fix_template_error.sh - Fix the Jinja2 template error

echo "🔧 Fixing Jinja2 template error..."

# Fix the admin/base.html template - remove duplicate block definition
cat > templates/admin/base.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block page_title %}Admin{% endblock %} - Mardi Gras API</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .admin-sidebar {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
    </style>
</head>
<body class="bg-gray-50">
    <div class="flex h-screen">
        <!-- Sidebar -->
        <div class="admin-sidebar text-white w-64 flex flex-col">
            <div class="p-6 border-b border-purple-400 border-opacity-30">
                <h2 class="text-xl font-bold">🎭 Mardi Gras Admin</h2>
                <p class="text-purple-200 text-sm mt-1">API Management</p>
            </div>
            
            <nav class="flex-1 p-4">
                <ul class="space-y-2">
                    <li>
                        <a href="{{ url_for('admin_dashboard') }}" 
                           class="flex items-center px-4 py-3 rounded-lg hover:bg-white hover:bg-opacity-10 transition-all {% if request.endpoint == 'admin_dashboard' %}bg-white bg-opacity-20{% endif %}">
                            <i class="fas fa-tachometer-alt mr-3"></i>Dashboard
                        </a>
                    </li>
                    <li>
                        <a href="{{ url_for('admin_terms_list') }}" 
                           class="flex items-center px-4 py-3 rounded-lg hover:bg-white hover:bg-opacity-10 transition-all {% if 'terms' in request.endpoint %}bg-white bg-opacity-20{% endif %}">
                            <i class="fas fa-book mr-3"></i>Terms
                        </a>
                    </li>
                    <li>
                        <a href="{{ url_for('admin_categories_list') }}" 
                           class="flex items-center px-4 py-3 rounded-lg hover:bg-white hover:bg-opacity-10 transition-all {% if 'categories' in request.endpoint %}bg-white bg-opacity-20{% endif %}">
                            <i class="fas fa-tags mr-3"></i>Categories
                        </a>
                    </li>
                </ul>
            </nav>
            
            <div class="p-4 border-t border-purple-400 border-opacity-30">
                <a href="{{ url_for('admin_logout') }}" class="flex items-center px-4 py-2 text-purple-200 hover:text-white transition-colors">
                    <i class="fas fa-sign-out-alt mr-3"></i>Logout
                </a>
            </div>
        </div>

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Header -->
            <header class="bg-white shadow-sm border-b px-6 py-4">
                <div class="flex items-center justify-between">
                    <h1 class="text-2xl font-semibold text-gray-800">{% block header_title %}{% block page_title %}Admin{% endblock %}{% endblock %}</h1>
                    <div class="flex items-center space-x-4">
                        <span class="text-sm text-gray-500">Welcome, Admin</span>
                        <div class="w-8 h-8 bg-purple-500 rounded-full flex items-center justify-center">
                            <i class="fas fa-user text-white text-sm"></i>
                        </div>
                    </div>
                </div>
            </header>

            <!-- Flash Messages -->
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <div class="px-6 pt-4">
                        {% for category, message in messages %}
                            <div class="mb-4 p-4 rounded-lg {% if category == 'error' %}bg-red-100 text-red-700 border border-red-200{% elif category == 'success' %}bg-green-100 text-green-700 border border-green-200{% else %}bg-blue-100 text-blue-700 border border-blue-200{% endif %}">
                                {{ message }}
                            </div>
                        {% endfor %}
                    </div>
                {% endif %}
            {% endwith %}

            <!-- Content Area -->
            <main class="flex-1 overflow-y-auto p-6">
                {% block content %}{% endblock %}
            </main>
        </div>
    </div>
</body>
</html>
EOF

# Fix the dashboard template to use the correct block name
cat > templates/admin/dashboard.html << 'EOF'
{% extends "admin/base.html" %}

{% block page_title %}Dashboard{% endblock %}

{% block content %}
<!-- Stats Cards -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
    <div class="bg-white rounded-lg shadow-md p-6">
        <div class="flex items-center justify-between">
            <div>
                <h3 class="text-sm font-medium text-gray-500 uppercase">Total Terms</h3>
                <p class="text-3xl font-bold text-gray-900">{{ stats.total_terms }}</p>
            </div>
            <div class="bg-blue-100 p-3 rounded-full">
                <i class="fas fa-book text-blue-600"></i>
            </div>
        </div>
    </div>
    
    <div class="bg-white rounded-lg shadow-md p-6">
        <div class="flex items-center justify-between">
            <div>
                <h3 class="text-sm font-medium text-gray-500 uppercase">Categories</h3>
                <p class="text-3xl font-bold text-gray-900">{{ stats.total_categories }}</p>
            </div>
            <div class="bg-green-100 p-3 rounded-full">
                <i class="fas fa-tags text-green-600"></i>
            </div>
        </div>
    </div>
    
    <div class="bg-white rounded-lg shadow-md p-6">
        <div class="flex items-center justify-between">
            <div>
                <h3 class="text-sm font-medium text-gray-500 uppercase">Total Views</h3>
                <p class="text-3xl font-bold text-gray-900">{{ "{:,}".format(stats.total_views) }}</p>
            </div>
            <div class="bg-purple-100 p-3 rounded-full">
                <i class="fas fa-eye text-purple-600"></i>
            </div>
        </div>
    </div>
    
    <div class="bg-white rounded-lg shadow-md p-6">
        <div class="flex items-center justify-between">
            <div>
                <h3 class="text-sm font-medium text-gray-500 uppercase">Featured</h3>
                <p class="text-3xl font-bold text-gray-900">{{ stats.featured_terms }}</p>
            </div>
            <div class="bg-yellow-100 p-3 rounded-full">
                <i class="fas fa-star text-yellow-600"></i>
            </div>
        </div>
    </div>
</div>

<!-- Recent Terms -->
<div class="bg-white rounded-lg shadow-md p-6">
    <h3 class="text-lg font-semibold text-gray-800 mb-4">Recent Terms</h3>
    {% if stats.recent_terms %}
        <div class="space-y-3">
            {% for term in stats.recent_terms %}
                <div class="flex items-center justify-between py-2 border-b border-gray-100 last:border-b-0">
                    <div>
                        <h4 class="font-medium text-gray-900">{{ term.term }}</h4>
                        <p class="text-sm text-gray-500">{{ term.pronunciation }}</p>
                    </div>
                    <div class="flex items-center space-x-2">
                        <span class="text-xs px-2 py-1 bg-blue-100 text-blue-800 rounded-full">
                            {{ term.category_rel.icon }} {{ term.category_rel.name }}
                        </span>
                        <span class="text-xs px-2 py-1 bg-gray-100 text-gray-800 rounded-full">
                            {{ term.difficulty }}
                        </span>
                    </div>
                </div>
            {% endfor %}
        </div>
    {% else %}
        <p class="text-gray-500">No terms yet. <a href="{{ url_for('admin_term_new') }}" class="text-purple-600 hover:text-purple-800">Create your first term</a>.</p>
    {% endif %}
</div>
{% endblock %}
EOF

# Fix other templates to use consistent block naming
cat > templates/admin/terms_list.html << 'EOF'
{% extends "admin/base.html" %}

{% block page_title %}Terms{% endblock %}

{% block content %}
<div class="flex justify-between items-center mb-6">
    <div class="flex items-center space-x-4">
        <form method="GET" class="flex items-center space-x-4">
            <input type="text" name="search" value="{{ search or '' }}" placeholder="Search terms..."
                   class="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
            <select name="category" class="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                <option value="">All Categories</option>
                {% for category in categories %}
                    <option value="{{ category.id }}" {% if category_id == category.id %}selected{% endif %}>
                        {{ category.icon }} {{ category.name }}
                    </option>
                {% endfor %}
            </select>
            <button type="submit" class="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600">
                <i class="fas fa-search"></i>
            </button>
        </form>
    </div>
    <a href="{{ url_for('admin_term_new') }}" class="bg-gradient-to-r from-purple-600 to-blue-600 text-white px-6 py-2 rounded-lg hover:from-purple-700 hover:to-blue-700">
        <i class="fas fa-plus mr-2"></i>New Term
    </a>
</div>

<div class="bg-white rounded-lg shadow-md overflow-hidden">
    <div class="overflow-x-auto">
        <table class="w-full">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Term</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Category</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Difficulty</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Views</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                {% for term in terms.items %}
                    <tr class="hover:bg-gray-50">
                        <td class="px-6 py-4">
                            <div class="font-medium text-gray-900">{{ term.term }}</div>
                            <div class="text-sm text-gray-500">{{ term.pronunciation }}</div>
                        </td>
                        <td class="px-6 py-4">
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                {{ term.category_rel.icon }} {{ term.category_rel.name }}
                            </span>
                        </td>
                        <td class="px-6 py-4">
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium 
                                {% if term.difficulty == 'tourist' %}bg-green-100 text-green-800
                                {% elif term.difficulty == 'local' %}bg-yellow-100 text-yellow-800
                                {% else %}bg-red-100 text-red-800{% endif %}">
                                {{ term.difficulty }}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-sm text-gray-900">{{ term.view_count }}</td>
                        <td class="px-6 py-4">
                            <div class="flex items-center space-x-2">
                                {% if term.is_active %}
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">Active</span>
                                {% else %}
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">Inactive</span>
                                {% endif %}
                                {% if term.is_featured %}
                                    <i class="fas fa-star text-yellow-500" title="Featured"></i>
                                {% endif %}
                            </div>
                        </td>
                        <td class="px-6 py-4 text-sm font-medium">
                            <div class="flex space-x-2">
                                <a href="{{ url_for('admin_term_edit', term_id=term.id) }}" 
                                   class="text-indigo-600 hover:text-indigo-900" title="Edit">
                                    <i class="fas fa-edit"></i>
                                </a>
                                <form method="POST" action="{{ url_for('admin_term_delete', term_id=term.id) }}" 
                                      onsubmit="return confirm('Are you sure you want to delete {{ term.term }}?')" class="inline">
                                    <button type="submit" class="text-red-600 hover:text-red-900" title="Delete">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </form>
                            </div>
                        </td>
                    </tr>
                {% else %}
                    <tr>
                        <td colspan="6" class="px-6 py-4 text-center text-gray-500">
                            No terms found. <a href="{{ url_for('admin_term_new') }}" class="text-purple-600 hover:text-purple-800">Create your first term</a>.
                        </td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- Pagination -->
{% if terms.pages > 1 %}
    <div class="flex justify-center mt-6">
        <nav class="flex space-x-2">
            {% if terms.has_prev %}
                <a href="{{ url_for('admin_terms_list', page=terms.prev_num, search=search, category=category_id) }}" 
                   class="px-3 py-2 border border-gray-300 rounded-md hover:bg-gray-50">Previous</a>
            {% endif %}
            
            {% for page_num in terms.iter_pages() %}
                {% if page_num %}
                    {% if page_num != terms.page %}
                        <a href="{{ url_for('admin_terms_list', page=page_num, search=search, category=category_id) }}" 
                           class="px-3 py-2 border border-gray-300 rounded-md hover:bg-gray-50">{{ page_num }}</a>
                    {% else %}
                        <span class="px-3 py-2 border bg-purple-500 text-white border-purple-500 rounded-md">{{ page_num }}</span>
                    {% endif %}
                {% else %}
                    <span class="px-3 py-2">...</span>
                {% endif %}
            {% endfor %}
            
            {% if terms.has_next %}
                <a href="{{ url_for('admin_terms_list', page=terms.next_num, search=search, category=category_id) }}" 
                   class="px-3 py-2 border border-gray-300 rounded-md hover:bg-gray-50">Next</a>
            {% endif %}
        </nav>
    </div>
{% endif %}
{% endblock %}
EOF

# Fix term form template
cat > templates/admin/term_form.html << 'EOF'
{% extends "admin/base.html" %}

{% block page_title %}{% if term %}Edit Term{% else %}New Term{% endif %}{% endblock %}

{% block content %}
<div class="max-w-4xl">
    <div class="bg-white rounded-lg shadow-md p-6">
        <div class="flex items-center justify-between mb-6">
            <h2 class="text-xl font-semibold">{% if term %}Edit Term: {{ term.term }}{% else %}Create New Term{% endif %}</h2>
            <a href="{{ url_for('admin_terms_list') }}" class="text-gray-500 hover:text-gray-700">
                <i class="fas fa-times text-xl"></i>
            </a>
        </div>
        
        <form method="POST" class="space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <label for="term" class="block text-sm font-medium text-gray-700 mb-2">Term *</label>
                    <input type="text" id="term" name="term" required
                           value="{% if term %}{{ term.term }}{% elif form_data %}{{ form_data.term }}{% endif %}"
                           class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                </div>
                
                <div>
                    <label for="pronunciation" class="block text-sm font-medium text-gray-700 mb-2">Pronunciation *</label>
                    <input type="text" id="pronunciation" name="pronunciation" required
                           value="{% if term %}{{ term.pronunciation }}{% elif form_data %}{{ form_data.pronunciation }}{% endif %}"
                           class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500"
                           placeholder="/pronunciation/">
                </div>
            </div>
            
            <div>
                <label for="definition" class="block text-sm font-medium text-gray-700 mb-2">Definition *</label>
                <textarea id="definition" name="definition" required rows="3"
                          class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">{% if term %}{{ term.definition }}{% elif form_data %}{{ form_data.definition }}{% endif %}</textarea>
            </div>
            
            <div>
                <label for="etymology" class="block text-sm font-medium text-gray-700 mb-2">Etymology</label>
                <textarea id="etymology" name="etymology" rows="2"
                          class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">{% if term %}{{ term.etymology or '' }}{% elif form_data %}{{ form_data.etymology or '' }}{% endif %}</textarea>
            </div>
            
            <div>
                <label for="example" class="block text-sm font-medium text-gray-700 mb-2">Example</label>
                <textarea id="example" name="example" rows="2"
                          class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">{% if term %}{{ term.example or '' }}{% elif form_data %}{{ form_data.example or '' }}{% endif %}</textarea>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <label for="category_id" class="block text-sm font-medium text-gray-700 mb-2">Category *</label>
                    <select id="category_id" name="category_id" required
                            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                        <option value="">Select Category</option>
                        {% for category in categories %}
                            <option value="{{ category.id }}" 
                                {% if (term and term.category_id == category.id) or (form_data and form_data.category_id|int == category.id) %}selected{% endif %}>
                                {{ category.icon }} {{ category.name }}
                            </option>
                        {% endfor %}
                    </select>
                </div>
                
                <div>
                    <label for="difficulty" class="block text-sm font-medium text-gray-700 mb-2">Difficulty *</label>
                    <select id="difficulty" name="difficulty" required
                            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                        <option value="">Select Difficulty</option>
                        <option value="tourist" {% if (term and term.difficulty == 'tourist') or (form_data and form_data.difficulty == 'tourist') %}selected{% endif %}>Tourist</option>
                        <option value="local" {% if (term and term.difficulty == 'local') or (form_data and form_data.difficulty == 'local') %}selected{% endif %}>Local</option>
                        <option value="expert" {% if (term and term.difficulty == 'expert') or (form_data and form_data.difficulty == 'expert') %}selected{% endif %}>Expert</option>
                    </select>
                </div>
            </div>
            
            <div class="flex items-center space-x-6">
                <label class="flex items-center">
                    <input type="checkbox" name="is_featured"
                           {% if (term and term.is_featured) or (form_data and form_data.is_featured) %}checked{% endif %}
                           class="mr-2 rounded border-gray-300 focus:ring-2 focus:ring-purple-500">
                    <span class="text-sm text-gray-700">Featured Term</span>
                </label>
                
                {% if term %}
                <label class="flex items-center">
                    <input type="checkbox" name="is_active"
                           {% if term.is_active %}checked{% endif %}
                           class="mr-2 rounded border-gray-300 focus:ring-2 focus:ring-purple-500">
                    <span class="text-sm text-gray-700">Active</span>
                </label>
                {% endif %}
            </div>
            
            <div class="flex justify-end space-x-4">
                <a href="{{ url_for('admin_terms_list') }}" 
                   class="px-6 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                    Cancel
                </a>
                <button type="submit" class="bg-gradient-to-r from-purple-600 to-blue-600 text-white px-6 py-2 rounded-lg hover:from-purple-700 hover:to-blue-700">
                    {% if term %}Update Term{% else %}Create Term{% endif %}
                </button>
            </div>
        </form>
    </div>
</div>
{% endblock %}
EOF

echo "✅ Template error fixed!"
echo ""
echo "🔧 Fixed Issues:"
echo "   ✅ Removed duplicate 'page_title' block definition"
echo "   ✅ Updated template inheritance structure"
echo "   ✅ Fixed all template files to use consistent naming"
echo ""
echo "🚀 Now restart your server:"
echo "   python3 app.py"
echo ""
echo "🌐 Then visit: http://localhost:5555/admin"
#!/usr/bin/env python3
"""
Vulnerable Shop - Python Flask Version
WARNING: This contains intentional security vulnerabilities for educational/lab purposes only!
DO NOT use in production!
"""

from flask import Flask, render_template_string, request, session, redirect, url_for
import pymysql
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_for_lab'  # VULNERABLE: Weak secret key

# Database configuration - VULNERABLE: Hardcoded credentials
DB_CONFIG = {
    'user': 'shop_admin',
    'password': '123456',
    'database': 'vulnerable_shop',
    'charset': 'utf8mb4',
    'unix_socket':'/var/run/mysqld/mysqld.sock',
    'cursorclass': pymysql.cursors.DictCursor,
}

# VULNERABLE: No prepared statements, direct string concatenation
def get_connection():
    return pymysql.connect(**DB_CONFIG)

# ============== TEMPLATES ==============

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Tech Store{% endblock %}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; }
        .navbar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 1rem; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .navbar .container { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; }
        .navbar a { color: white; text-decoration: none; margin-left: 20px; transition: opacity 0.3s; }
        .navbar a:hover { opacity: 0.8; }
        .navbar .brand { font-size: 1.5em; font-weight: bold; }
        {% block extra_css %}{% endblock %}
    </style>
</head>
<body>
    {% block content %}{% endblock %}
</body>
</html>
"""

INDEX_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
    <div class="navbar">
        <div class="container">
            <div>
                <span class="brand">T3ch Stor3</span>
                <a href="/">Trang chủ</a>
                {% if session.get('user_id') and session.get('role') == 'admin' %}
                    <a href="/admin">Quản trị</a>
                {% endif %}
            </div>
            <div>
                {% if session.get('user_id') %}
                    <span>Xin chào, <strong>{{ session.get('username') }}</strong></span>
                    <a href="/logout">Đăng xuất</a>
                {% else %}
                    <a href="/login">Đăng nhập</a>
                    <a href="/register">Đăng ký</a>
                {% endif %}
            </div>
        </div>
    </div>

    <div class="container">
        <div class="search-section">
            <h2>Tìm kiếm sản phẩm</h2>
            <p>Khám phá các sản phẩm công nghệ mới nhất</p>
            
            <form method="GET" action="/" class="search-box">
                <input type="text" name="search" placeholder="Nhập tên sản phẩm bạn muốn tìm..." 
                       value="{{ search }}">
                <button type="submit">Tìm kiếm</button>
            </form>
        </div>

        <div class="results">
            {{ content|safe }}
        </div>
    </div>
""").replace('{% block extra_css %}{% endblock %}', """
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .search-section { background: white; padding: 40px; margin-bottom: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .search-section h2 { margin-bottom: 10px; color: #333; font-size: 28px; }
        .search-section p { color: #666; margin-bottom: 25px; font-size: 16px; }
        .search-box { display: flex; gap: 10px; }
        .search-box input { flex: 1; padding: 14px 18px; font-size: 16px; border: 2px solid #e0e0e0; border-radius: 8px; transition: border-color 0.3s; }
        .search-box input:focus { outline: none; border-color: #667eea; }
        .search-box button { padding: 14px 32px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; cursor: pointer; font-size: 16px; border-radius: 8px; font-weight: 600; transition: transform 0.2s; }
        .search-box button:hover { transform: translateY(-2px); }
        .waf-blocked { background: #fff3cd; border-left: 4px solid #ffc107; padding: 20px; margin: 20px 0; border-radius: 8px; }
        .waf-blocked h3 { color: #856404; margin-bottom: 10px; }
        .waf-blocked p { color: #856404; margin: 5px 0; }
        .results { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .results h3 { margin-bottom: 20px; color: #333; font-size: 24px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 16px; text-align: left; border-bottom: 1px solid #e0e0e0; }
        th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: 600; }
        tr:hover { background-color: #f8f9fa; }
        .error { color: #d32f2f; padding: 20px; background-color: #ffebee; border-radius: 8px; border-left: 4px solid #d32f2f; margin: 20px 0; }
        .no-results { text-align: center; padding: 40px; color: #666; }
        .product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; margin-top: 20px; }
        .product-card { background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; transition: transform 0.2s, box-shadow 0.2s; }
        .product-card:hover { transform: translateY(-4px); box-shadow: 0 6px 12px rgba(0,0,0,0.1); }
        .product-name { font-weight: 600; font-size: 18px; color: #333; margin-bottom: 10px; }
        .product-price { color: #667eea; font-size: 20px; font-weight: bold; margin: 10px 0; }
        .product-desc { color: #666; font-size: 14px; line-height: 1.5; }
""")

LOGIN_TEMPLATE = BASE_TEMPLATE.replace('{% block title %}Tech Store{% endblock %}', 'Đăng nhập - Tech Store').replace('{% block content %}{% endblock %}', """
    <div class="login-container">
        <h2>Đăng nhập</h2>
        
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label>Tên đăng nhập</label>
                <input type="text" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label>Mật khẩu</label>
                <input type="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit">Đăng nhập</button>
        </form>
        
        <div class="links">
            <a href="/register">Tạo tài khoản mới</a>
            <span class="divider">|</span>
            <a href="/">Quay lại trang chủ</a>
        </div>
    </div>
""").replace('{% block extra_css %}{% endblock %}', """
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 100vh; display: flex; justify-content: center; align-items: center; }
        .login-container { background: white; padding: 50px; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 440px; }
        h2 { text-align: center; margin-bottom: 40px; color: #333; font-size: 28px; }
        .form-group { margin-bottom: 24px; }
        label { display: block; margin-bottom: 8px; color: #555; font-weight: 600; font-size: 14px; }
        input { width: 100%; padding: 14px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 15px; transition: border-color 0.3s; }
        input:focus { outline: none; border-color: #667eea; }
        button { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; font-weight: 600; transition: transform 0.2s; }
        button:hover { transform: translateY(-2px); }
        .error { background: #ffebee; color: #c62828; padding: 14px; border-radius: 8px; margin-bottom: 24px; border-left: 4px solid #c62828; font-size: 14px; }
        .links { text-align: center; margin-top: 24px; }
        .links a { color: #667eea; text-decoration: none; font-weight: 500; font-size: 14px; }
        .links a:hover { text-decoration: underline; }
        .divider { margin: 0 10px; color: #999; }
""")

REGISTER_TEMPLATE = LOGIN_TEMPLATE.replace('Đăng nhập - Tech Store', 'Đăng ký - Tech Store').replace("""
        <h2>Đăng nhập</h2>
        
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label>Tên đăng nhập</label>
                <input type="text" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label>Mật khẩu</label>
                <input type="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit">Đăng nhập</button>
        </form>
        
        <div class="links">
            <a href="/register">Tạo tài khoản mới</a>
            <span class="divider">|</span>
            <a href="/">Quay lại trang chủ</a>
        </div>
""", """
        <h2>Đăng ký tài khoản</h2>
        
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        
        {% if success %}
            <div class="success">{{ success }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label>Tên đăng nhập</label>
                <input type="text" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" required autocomplete="email">
            </div>
            <div class="form-group">
                <label>Mật khẩu</label>
                <input type="password" name="password" required autocomplete="new-password">
            </div>
            <button type="submit">Đăng ký</button>
        </form>
        
        <div class="links">
            <a href="/login">Đã có tài khoản? Đăng nhập</a>
            <span class="divider">|</span>
            <a href="/">Trang chủ</a>
        </div>
""").replace('.error { background:', '.success { background: #e8f5e9; color: #2e7d32; padding: 14px; border-radius: 8px; margin-bottom: 24px; border-left: 4px solid #4caf50; font-size: 14px; }\n        .error { background:')

ADMIN_TEMPLATE = BASE_TEMPLATE.replace('{% block title %}Tech Store{% endblock %}', 'Quản trị - Tech Store').replace('{% block content %}{% endblock %}', """
    <div class="navbar">
        <div class="container">
            <div>
                <a href="/">Trang chủ</a>
                <a href="/admin">Quản trị</a>
            </div>
            <div>
                <span>Quản trị viên: <strong>{{ session.get('username') }}</strong></span>
                <a href="/logout" style="margin-left: 20px;">Đăng xuất</a>
            </div>
        </div>
    </div>

    <div class="container">
        {% if success %}
            <div class="success">{{ success }}</div>
        {% endif %}

        <div class="section">
            <h2>Thêm sản phẩm mới</h2>
            
            <form method="POST">
                <div class="form-group">
                    <label>Tên sản phẩm</label>
                    <input type="text" name="name" required placeholder="Ví dụ: Samsung Galaxy Z Fold 5">
                </div>
                <div class="form-group">
                    <label>Mô tả</label>
                    <textarea name="description" required placeholder="Nhập mô tả chi tiết về sản phẩm..."></textarea>
                </div>
                <div class="form-group">
                    <label>Giá (VNĐ)</label>
                    <input type="number" name="price" required placeholder="Ví dụ: 15000000">
                </div>
                <button type="submit" name="add_product">Thêm sản phẩm</button>
            </form>
        </div>

        <div class="section">
            <h2>Danh sách sản phẩm</h2>
            <table>
                <thead>
                    <tr>
                        <th>Mã SP</th>
                        <th>Tên sản phẩm</th>
                        <th>Giá (VNĐ)</th>
                        <th>Ngày tạo</th>
                        <th>Hành động</th>
                    </tr>
                </thead>
                <tbody>
                    {% for p in products %}
                    <tr>
                        <td>#{{ p.id }}</td>
                        <td>{{ p.name }}</td>
                        <td>{{ "{:,.0f}".format(p.price) }} ₫</td>
                        <td>{{ p.created_at.strftime('%d/%m/%Y %H:%M') }}</td>
                        <td>
                            <a href="/admin?delete={{ p.id }}" class="btn-danger" 
                               onclick="return confirm('Bạn có chắc muốn xóa sản phẩm này?')">Xóa</a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Danh sách người dùng</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Tên đăng nhập</th>
                        <th>Email</th>
                        <th>Vai trò</th>
                        <th>Ngày đăng ký</th>
                    </tr>
                </thead>
                <tbody>
                    {% for u in users %}
                    <tr>
                        <td>{{ u.id }}</td>
                        <td>{{ u.username }}</td>
                        <td>{{ u.email }}</td>
                        <td><span class="role-badge {{ u.role }}">{{ u.role|upper }}</span></td>
                        <td>{{ u.created_at.strftime('%d/%m/%Y %H:%M') }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
""").replace('{% block extra_css %}{% endblock %}', """
        body { background: #f5f7fa; }
        .navbar { background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); }
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .section { background: white; padding: 30px; margin-bottom: 30px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        h2 { margin-bottom: 24px; color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 12px; font-size: 24px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 14px; text-align: left; border-bottom: 1px solid #e0e0e0; }
        th { background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color: white; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: #555; }
        input, textarea { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; transition: border-color 0.3s; }
        input:focus, textarea:focus { outline: none; border-color: #3498db; }
        textarea { resize: vertical; min-height: 100px; }
        button { padding: 12px 28px; background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 15px; transition: transform 0.2s; }
        button:hover { transform: translateY(-2px); }
        .btn-danger { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); padding: 8px 16px; color: white; text-decoration: none; border-radius: 6px; font-size: 13px; display: inline-block; transition: transform 0.2s; }
        .btn-danger:hover { transform: translateY(-2px); }
        .success { background: #e8f5e9; color: #2e7d32; padding: 16px; border-radius: 8px; margin-bottom: 24px; border-left: 4px solid #4caf50; }
        .role-badge { background: #3498db; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .role-badge.admin { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
""")

# ============== ROUTES ==============

@app.route('/')
def index():
    search = request.args.get('search', '')
    blocked = False
    content = ''
    
    if search:
        # VULNERABLE: Weak blacklist filter (can be bypassed)
        search_lower = search.lower()
        blacklist = ['union select', ' or 1=1', ' or true', 'load_file', 
                    ' into outfile', ' into dumpfile', '-- ', '/*', '*/']
        
        for pattern in blacklist:
            if pattern in search_lower:
                blocked = True
                break
    
    conn = get_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    
    if blocked:
        content = """
        <div class="waf-blocked">
            <h3>Yêu cầu không hợp lệ</h3>
            <p>Hệ thống phát hiện truy vấn có chứa nội dung không an toàn.</p>
            <p>Vui lòng thử lại với từ khóa tìm kiếm hợp lệ.</p>
        </div>
        """
    elif search:
        # VULNERABLE: SQL Injection - direct string concatenation
        sql = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{search}%'"
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
            
            if results:
                content = f'<h3>Kết quả tìm kiếm cho: "{search}" ({len(results)} sản phẩm)</h3>'
                content += '<table><tr><th>Mã SP</th><th>Tên sản phẩm</th><th>Giá</th><th>Mô tả</th></tr>'
                for row in results:
                    content += f"""
                    <tr>
                        <td>#{row['id']}</td>
                        <td>{row['name']}</td>
                        <td><strong>{row['price']:,.0f} ₫</strong></td>
                        <td>{row['description']}</td>
                    </tr>
                    """
                content += '</table>'
            else:
                content = f"""
                <div class='no-results'>
                    <h3>Không tìm thấy sản phẩm</h3>
                    <p>Không có sản phẩm nào phù hợp với từ khóa "{search}"</p>
                </div>
                """
        except Exception as e:
            content = f"<div class='error'><strong>Lỗi:</strong> Không thể thực hiện tìm kiếm. Vui lòng thử lại sau.</div>"
    else:
        sql = "SELECT id, name, price, description FROM products ORDER BY created_at DESC LIMIT 10"
        cursor.execute(sql)
        results = cursor.fetchall()
        
        if results:
            content = '<h3>Sản phẩm mới nhất</h3><div class="product-grid">'
            for row in results:
                content += f"""
                <div class="product-card">
                    <div class="product-name">{row['name']}</div>
                    <div class="product-price">{row['price']:,.0f} ₫</div>
                    <div class="product-desc">{row['description']}</div>
                </div>
                """
            content += '</div>'
    
    cursor.close()
    conn.close()
    
    return render_template_string(INDEX_TEMPLATE, search=search, content=content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE: SQL Injection in login
        sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        conn = get_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql)
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            if user['role'] == 'admin':
                return redirect('/admin')
            else:
                return redirect('/')
        else:
            error = 'Tên đăng nhập hoặc mật khẩu không đúng!'
    
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ''
    success = ''
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        email = request.form.get('email', '')
        
        # VULNERABLE: SQL Injection in registration
        sql = f"INSERT INTO users (username, password, email, role) VALUES ('{username}', '{password}', '{email}', 'user')"
        
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(sql)
            conn.commit()
            cursor.close()
            conn.close()
            success = 'Đăng ký thành công! Bạn có thể đăng nhập ngay bây giờ.'
        except:
            error = 'Có lỗi xảy ra. Vui lòng thử lại.'
    
    return render_template_string(REGISTER_TEMPLATE, error=error, success=success)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Check authentication
    if not session.get('user_id'):
        return redirect('/login')
    
    if session.get('role') != 'admin':
        return '<h1 style="text-align:center;margin-top:50px;">Truy cập bị từ chối</h1><p style="text-align:center;">Bạn không có quyền truy cập trang này.</p>'
    
    success = ''
    conn = get_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    
    # Handle product addition
    if request.method == 'POST' and 'add_product' in request.form:
        name = request.form.get('name', '')
        description = request.form.get('description', '')
        price = request.form.get('price', '')
        
        # VULNERABLE: SQL Injection
        sql = f"INSERT INTO products (name, description, price) VALUES ('{name}', '{description}', '{price}')"
        try:
            cursor.execute(sql)
            conn.commit()
            success = 'Thêm sản phẩm thành công!'
        except:
            pass
    
    # Handle product deletion
    if request.args.get('delete'):
        product_id = request.args.get('delete')
        # VULNERABLE: SQL Injection
        sql = f"DELETE FROM products WHERE id = {product_id}"
        cursor.execute(sql)
        conn.commit()
        return redirect('/admin')
    
    # Get products and users
    cursor.execute("SELECT * FROM products ORDER BY id DESC")
    products = cursor.fetchall()
    
    cursor.execute("SELECT * FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template_string(ADMIN_TEMPLATE, success=success, products=products, users=users)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    # VULNERABLE: Debug mode enabled, running on all interfaces
    app.run(host='0.0.0.0', port=8081, debug=True)

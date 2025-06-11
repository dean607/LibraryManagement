"""完整圖書管理系統 - 整合版本"""

from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import hashlib
import os

app = Flask(__name__)
app.secret_key = "library_management_system_2024"

DATABASE = "library_system.db"

def get_db_connection() -> sqlite3.Connection:
    """取得資料庫連線"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """初始化資料庫與預設資料"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 會員表
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS members (
        mid TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        phone TEXT,
        birthdate TEXT,
        user_type TEXT DEFAULT 'user',
        created_date TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # 圖書表
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS books (
        bid TEXT PRIMARY KEY,
        btitle TEXT NOT NULL,
        bauthor TEXT NOT NULL,
        bpublisher TEXT,
        bprice INTEGER NOT NULL,
        bstock INTEGER NOT NULL,
        total_stock INTEGER NOT NULL,
        bcategory TEXT,
        created_date TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # 借閱記錄表
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS borrow_records (
        record_id INTEGER PRIMARY KEY AUTOINCREMENT,
        mid TEXT NOT NULL,
        bid TEXT NOT NULL,
        borrow_date TEXT NOT NULL,
        due_date TEXT NOT NULL,
        return_date TEXT,
        status TEXT DEFAULT 'borrowed',
        fine_amount INTEGER DEFAULT 0,
        FOREIGN KEY (mid) REFERENCES members (mid),
        FOREIGN KEY (bid) REFERENCES books (bid)
    );
    """)
    
    # 銷售記錄表（保留原有功能）
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sale_records (
        sid INTEGER PRIMARY KEY AUTOINCREMENT,
        sdate TEXT NOT NULL,
        mid TEXT NOT NULL,
        bid TEXT NOT NULL,
        sqty INTEGER NOT NULL,
        sdiscount INTEGER NOT NULL,
        stotal INTEGER NOT NULL,
        FOREIGN KEY (mid) REFERENCES members (mid),
        FOREIGN KEY (bid) REFERENCES books (bid)
    );
    """)
    
    # 插入預設管理員
    cursor.execute("""
    INSERT OR IGNORE INTO members (mid, username, email, password, user_type)
    VALUES ('ADMIN001', 'admin', 'admin@library.com', ?, 'admin')
    """, (hashlib.md5('admin123'.encode()).hexdigest(),))
    
    # 插入預設圖書資料
    default_books = [
        ('B001', 'Python程式設計', '張三', '科技出版社', 600, 10, 15, '程式設計'),
        ('B002', '資料科學入門', '李四', '數據出版社', 800, 8, 12, '資料科學'),
        ('B003', '機器學習指南', '王五', 'AI出版社', 1200, 5, 8, '人工智慧'),
        ('B004', 'Flask網頁開發', '趙六', 'Web出版社', 750, 12, 18, '網頁開發'),
        ('B005', '資料庫設計', '錢七', '系統出版社', 650, 15, 20, '資料庫')
    ]
    
    for book in default_books:
        cursor.execute("""
        INSERT OR IGNORE INTO books (bid, btitle, bauthor, bpublisher, bprice, bstock, total_stock, bcategory)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, book)
    
    conn.commit()
    conn.close()

# 工具函數
def hash_password(password: str) -> str:
    """密碼加密"""
    return hashlib.md5(password.encode()).hexdigest()

def validate_date(date_str: str) -> bool:
    """驗證日期格式"""
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def calculate_due_date(borrow_date: str, days: int = 14) -> str:
    """計算到期日期"""
    borrow_dt = datetime.strptime(borrow_date, '%Y-%m-%d')
    due_dt = borrow_dt + timedelta(days=days)
    return due_dt.strftime('%Y-%m-%d')

def is_admin() -> bool:
    """檢查是否為管理員"""
    return session.get('user_type') == 'admin'

def login_required(f):
    """登入檢查裝飾器"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """管理員權限檢查裝飾器"""
    def decorated_function(*args, **kwargs):
        if not is_admin():
            flash('需要管理員權限')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# 路由定義
@app.route("/")
def index():
    """首頁"""
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """會員註冊"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        phone = request.form.get("phone", "").strip()
        birthdate = request.form.get("birthdate", "").strip()
        
        if not username or not email or not password:
            flash("請輸入用戶名、電子郵件和密碼")
            return render_template("register.html")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 檢查用戶名是否已存在
        existing_user = cursor.execute("SELECT * FROM members WHERE username = ?", (username,)).fetchone()
        if existing_user:
            flash("用戶名已存在")
            conn.close()
            return render_template("register.html")
        
        try:
            # 生成會員編號
            cursor.execute("SELECT COUNT(*) FROM members WHERE user_type = 'user'")
            user_count = cursor.fetchone()[0]
            mid = f"M{user_count + 1:03d}"
            
            # 插入新會員
            cursor.execute("""
            INSERT INTO members (mid, username, email, password, phone, birthdate)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (mid, username, email, hash_password(password), phone, birthdate))
            
            conn.commit()
            flash("註冊成功！請登入")
            return redirect(url_for("login"))
            
        except sqlite3.IntegrityError:
            flash("電子郵件已被使用")
        finally:
            conn.close()
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """會員登入"""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        
        if not email or not password:
            flash("請輸入電子郵件和密碼")
            return render_template("login.html")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        user = cursor.execute("""
        SELECT * FROM members WHERE email = ? AND password = ?
        """, (email, hash_password(password))).fetchone()
        
        conn.close()
        
        if user:
            session['user_id'] = user['mid']
            session['username'] = user['username']
            session['user_type'] = user['user_type']
            
            if user['user_type'] == 'admin':
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("user_dashboard"))
        else:
            flash("電子郵件或密碼錯誤")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    """登出"""
    session.clear()
    flash("已成功登出")
    return redirect(url_for("index"))

@app.route("/user_dashboard")
@login_required
def user_dashboard():
    """用戶儀表板 - 擴充版本"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 獲取用戶基本資訊
    user_info = cursor.execute("""
    SELECT * FROM members WHERE mid = ?
    """, (session['user_id'],)).fetchone()
    
    # 獲取目前借閱記錄
    borrow_records = cursor.execute("""
    SELECT br.*, b.btitle, b.bauthor 
    FROM borrow_records br
    JOIN books b ON br.bid = b.bid
    WHERE br.mid = ? AND br.status = 'borrowed'
    ORDER BY br.borrow_date DESC
    """, (session['user_id'],)).fetchall()
    
    # 計算借閱統計
    total_borrowed_count = cursor.execute("""
    SELECT COUNT(*) FROM borrow_records WHERE mid = ?
    """, (session['user_id'],)).fetchone()[0]
    
    # 獲取完整借閱歷史
    borrow_history = cursor.execute("""
    SELECT br.*, b.btitle, b.bauthor 
    FROM borrow_records br
    JOIN books b ON br.bid = b.bid
    WHERE br.mid = ?
    ORDER BY br.borrow_date DESC
    LIMIT 20
    """, (session['user_id'],)).fetchall()
    
    # 處理逾期和即將到期的記錄
    current_date = datetime.now().date()
    overdue_records = []
    due_soon_records = []
    overdue_count = 0
    
    for record in borrow_records:
        due_date = datetime.strptime(record['due_date'], '%Y-%m-%d').date()
        days_diff = (current_date - due_date).days
        
        # 增加計算欄位
        record_dict = dict(record)
        
        if days_diff > 0:  # 已逾期
            record_dict['is_overdue'] = True
            record_dict['overdue_days'] = days_diff
            overdue_records.append(record_dict)
            overdue_count += 1
        elif days_diff >= -3:  # 3天內到期
            record_dict['due_soon'] = True
            record_dict['days_until_due'] = abs(days_diff)
            due_soon_records.append(record_dict)
        
        # 計算續借後的到期日
        record_dict['new_due_date'] = calculate_due_date(record['due_date'], 14)
    
    # 計算會員天數
    created_date = datetime.strptime(user_info['created_date'][:10], '%Y-%m-%d').date()
    member_days = (current_date - created_date).days
    
    conn.close()
    
    return render_template("user_dashboard.html",
                         username=session['username'],
                         user_info=user_info,
                         borrow_records=borrow_records,
                         borrow_history=borrow_history,
                         total_borrowed_count=total_borrowed_count,
                         overdue_records=overdue_records,
                         due_soon_records=due_soon_records,
                         overdue_count=overdue_count,
                         member_days=member_days)

@app.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    """更新個人資料"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        birthdate = request.form.get("birthdate", "").strip()
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        
        # 檢查必填欄位
        if not username or not email:
            flash("用戶名和電子郵件為必填欄位")
            return redirect(url_for("user_dashboard"))
        
        # 檢查用戶名是否被其他用戶使用
        existing_user = cursor.execute("""
        SELECT mid FROM members WHERE username = ? AND mid != ?
        """, (username, session['user_id'])).fetchone()
        
        if existing_user:
            flash("用戶名已被使用")
            return redirect(url_for("user_dashboard"))
        
        # 檢查電子郵件是否被其他用戶使用
        existing_email = cursor.execute("""
        SELECT mid FROM members WHERE email = ? AND mid != ?
        """, (email, session['user_id'])).fetchone()
        
        if existing_email:
            flash("電子郵件已被使用")
            return redirect(url_for("user_dashboard"))
        
        # 如果要修改密碼
        if new_password:
            if not current_password:
                flash("請輸入目前密碼")
                return redirect(url_for("user_dashboard"))
            
            # 驗證目前密碼
            user = cursor.execute("""
            SELECT password FROM members WHERE mid = ?
            """, (session['user_id'],)).fetchone()
            
            if user['password'] != hash_password(current_password):
                flash("目前密碼錯誤")
                return redirect(url_for("user_dashboard"))
            
            # 更新包含密碼
            cursor.execute("""
            UPDATE members 
            SET username = ?, email = ?, phone = ?, birthdate = ?, password = ?
            WHERE mid = ?
            """, (username, email, phone, birthdate, hash_password(new_password), session['user_id']))
        else:
            # 更新不包含密碼
            cursor.execute("""
            UPDATE members 
            SET username = ?, email = ?, phone = ?, birthdate = ?
            WHERE mid = ?
            """, (username, email, phone, birthdate, session['user_id']))
        
        conn.commit()
        session['username'] = username  # 更新 session 中的用戶名
        flash("個人資料更新成功")
        
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"更新失敗：{e}")
    finally:
        conn.close()
    
    return redirect(url_for("user_dashboard"))

@app.route("/renew_book/<int:record_id>", methods=["POST"])
@login_required
def renew_book(record_id):
    """續借圖書"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 檢查借閱記錄
        record = cursor.execute("""
        SELECT br.*, b.btitle FROM borrow_records br
        JOIN books b ON br.bid = b.bid
        WHERE br.record_id = ? AND br.mid = ? AND br.status = 'borrowed'
        """, (record_id, session['user_id'])).fetchone()
        
        if not record:
            flash("借閱記錄不存在")
            return redirect(url_for("user_dashboard"))
        
        # 檢查是否已逾期
        due_date = datetime.strptime(record['due_date'], '%Y-%m-%d').date()
        current_date = datetime.now().date()
        
        if current_date > due_date:
            flash("逾期圖書無法續借，請先歸還")
            return redirect(url_for("user_dashboard"))
        
        # 檢查續借次數（假設最多續借2次）
        renew_count = cursor.execute("""
        SELECT COUNT(*) FROM borrow_records 
        WHERE mid = ? AND bid = ? AND borrow_date >= date('now', '-60 days')
        """, (session['user_id'], record['bid'])).fetchone()[0]
        
        if renew_count > 2:
            flash("此圖書已達續借上限")
            return redirect(url_for("user_dashboard"))
        
        # 計算新的到期日
        new_due_date = calculate_due_date(record['due_date'], 14)
        
        # 更新到期日
        cursor.execute("""
        UPDATE borrow_records SET due_date = ? WHERE record_id = ?
        """, (new_due_date, record_id))
        
        conn.commit()
        flash(f"《{record['btitle']}》續借成功，新到期日：{new_due_date}")
        
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"續借失敗：{e}")
    finally:
        conn.close()
    
    return redirect(url_for("user_dashboard"))

@app.route("/update_notification_settings", methods=["POST"])
@login_required
def update_notification_settings():
    """更新通知設定"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        email_reminder = request.form.get("email_reminder") == "on"
        overdue_alert = request.form.get("overdue_alert") == "on"
        
        # 先檢查是否有 notification_settings 欄位，如果沒有則新增
        cursor.execute("PRAGMA table_info(members)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'email_reminder' not in columns:
            cursor.execute("ALTER TABLE members ADD COLUMN email_reminder BOOLEAN DEFAULT 0")
            cursor.execute("ALTER TABLE members ADD COLUMN overdue_alert BOOLEAN DEFAULT 0")
        
        cursor.execute("""
        UPDATE members 
        SET email_reminder = ?, overdue_alert = ?
        WHERE mid = ?
        """, (email_reminder, overdue_alert, session['user_id']))
        
        conn.commit()
        flash("通知設定已更新")
        
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"更新失敗：{e}")
    finally:
        conn.close()
    
    return redirect(url_for("user_dashboard"))

@app.route("/admin_dashboard")
@login_required
@admin_required
def admin_dashboard():
    """管理員儀表板 - 擴充版本"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 統計資料
    stats = {}
    stats['total_books'] = cursor.execute("SELECT COUNT(*) FROM books").fetchone()[0]
    stats['total_members'] = cursor.execute("SELECT COUNT(*) FROM members WHERE user_type = 'user'").fetchone()[0]
    stats['borrowed_books'] = cursor.execute("SELECT COUNT(*) FROM borrow_records WHERE status = 'borrowed'").fetchone()[0]
    stats['overdue_books'] = cursor.execute("""
    SELECT COUNT(*) FROM borrow_records 
    WHERE status = 'borrowed' AND due_date < date('now')
    """).fetchone()[0]
    
    # 獲取所有借出圖書的詳細資訊（包含剩餘天數計算）
    borrowed_books = cursor.execute("""
    SELECT br.*, m.username, b.btitle, b.bauthor,
           julianday(br.due_date) - julianday('now') AS days_remaining
    FROM borrow_records br
    JOIN members m ON br.mid = m.mid
    JOIN books b ON br.bid = b.bid
    WHERE br.status = 'borrowed' AND br.due_date >= date('now')
    ORDER BY br.due_date ASC
    """).fetchall()
    
    # 獲取所有逾期圖書的詳細資訊
    overdue_books = cursor.execute("""
    SELECT br.*, m.username, b.btitle, b.bauthor,
           julianday('now') - julianday(br.due_date) AS overdue_days
    FROM borrow_records br
    JOIN members m ON br.mid = m.mid
    JOIN books b ON br.bid = b.bid
    WHERE br.status = 'borrowed' AND br.due_date < date('now')
    ORDER BY br.due_date ASC
    """).fetchall()
    
    # 計算總逾期罰金
    total_overdue_fine = sum(int(record['overdue_days']) * 5 for record in overdue_books)
    
    conn.close()
    
    return render_template("admin_dashboard.html", 
                          stats=stats, 
                          borrowed_books=borrowed_books, 
                          overdue_books=overdue_books,
                          total_overdue_fine=total_overdue_fine)


@app.route("/books")
@login_required
def list_books():
    """圖書列表"""
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM books WHERE 1=1"
    params = []
    
    if search:
        query += " AND (btitle LIKE ? OR bauthor LIKE ?)"
        params.extend([f'%{search}%', f'%{search}%'])
    
    if category:
        query += " AND bcategory = ?"
        params.append(category)
    
    query += " ORDER BY btitle"
    
    books = cursor.execute(query, params).fetchall()
    
    # 獲取所有分類
    categories = cursor.execute("SELECT DISTINCT bcategory FROM books ORDER BY bcategory").fetchall()
    
    conn.close()
    
    return render_template("books.html", books=books, categories=categories, search=search, category=category)

@app.route("/borrow_book/<bid>", methods=["POST"])
@login_required
def borrow_book(bid):
    """借書"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 檢查圖書是否存在且有庫存
    book = cursor.execute("SELECT * FROM books WHERE bid = ?", (bid,)).fetchone()
    if not book or book['bstock'] <= 0:
        flash("圖書不存在或庫存不足")
        return redirect(url_for("list_books"))
    
    # 檢查用戶是否已借閱此書
    existing_borrow = cursor.execute("""
    SELECT * FROM borrow_records 
    WHERE mid = ? AND bid = ? AND status = 'borrowed'
    """, (session['user_id'], bid)).fetchone()
    
    if existing_borrow:
        flash("您已借閱此書，請先歸還後再借閱")
        return redirect(url_for("list_books"))
    
    # 檢查用戶借閱數量限制（假設最多借5本）
    current_borrows = cursor.execute("""
    SELECT COUNT(*) FROM borrow_records 
    WHERE mid = ? AND status = 'borrowed'
    """, (session['user_id'],)).fetchone()[0]
    
    if current_borrows >= 5:
        flash("您已達到借閱上限（5本），請先歸還部分圖書")
        return redirect(url_for("list_books"))
    
    try:
        # 建立借閱記錄
        borrow_date = datetime.now().strftime('%Y-%m-%d')
        due_date = calculate_due_date(borrow_date, 14)
        
        cursor.execute("""
        INSERT INTO borrow_records (mid, bid, borrow_date, due_date, status)
        VALUES (?, ?, ?, ?, 'borrowed')
        """, (session['user_id'], bid, borrow_date, due_date))
        
        # 更新圖書庫存
        cursor.execute("UPDATE books SET bstock = bstock - 1 WHERE bid = ?", (bid,))
        
        conn.commit()
        flash(f"成功借閱《{book['btitle']}》，請於{due_date}前歸還")
        
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"借閱失敗：{e}")
    finally:
        conn.close()
    
    return redirect(url_for("list_books"))

@app.route("/return_book/<int:record_id>", methods=["POST"])
@login_required
def return_book(record_id):
    """還書"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 檢查借閱記錄
    record = cursor.execute("""
    SELECT br.*, b.btitle FROM borrow_records br
    JOIN books b ON br.bid = b.bid
    WHERE br.record_id = ? AND br.mid = ? AND br.status = 'borrowed'
    """, (record_id, session['user_id'])).fetchone()
    
    if not record:
        flash("借閱記錄不存在")
        return redirect(url_for("user_dashboard"))
    
    try:
        return_date = datetime.now().strftime('%Y-%m-%d')
        
        # 計算逾期罰金
        due_date = datetime.strptime(record['due_date'], '%Y-%m-%d')
        return_dt = datetime.strptime(return_date, '%Y-%m-%d')
        fine_amount = 0
        
        if return_dt > due_date:
            overdue_days = (return_dt - due_date).days
            fine_amount = overdue_days * 5  # 每天罰金5元
        
        # 更新借閱記錄
        cursor.execute("""
        UPDATE borrow_records 
        SET return_date = ?, status = 'returned', fine_amount = ?
        WHERE record_id = ?
        """, (return_date, fine_amount, record_id))
        
        # 更新圖書庫存
        cursor.execute("UPDATE books SET bstock = bstock + 1 WHERE bid = ?", (record['bid'],))
        
        conn.commit()
        
        if fine_amount > 0:
            flash(f"成功歸還《{record['btitle']}》，逾期罰金：{fine_amount}元")
        else:
            flash(f"成功歸還《{record['btitle']}》")
            
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"還書失敗：{e}")
    finally:
        conn.close()
    
    return redirect(url_for("user_dashboard"))

@app.route("/admin/books")
@login_required
@admin_required
def admin_books():
    """管理員圖書管理"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    books = cursor.execute("SELECT * FROM books ORDER BY btitle").fetchall()
    conn.close()
    
    return render_template("admin_books.html", books=books)

@app.route("/admin/add_book", methods=["GET", "POST"])
@login_required
@admin_required
def add_book():
    """新增圖書"""
    if request.method == "POST":
        btitle = request.form.get("btitle", "").strip()
        bauthor = request.form.get("bauthor", "").strip()
        bpublisher = request.form.get("bpublisher", "").strip()
        bprice = request.form.get("bprice", "0")
        bstock = request.form.get("bstock", "0")
        bcategory = request.form.get("bcategory", "").strip()
        
        if not btitle or not bauthor:
            flash("請輸入書名和作者")
            return render_template("add_book.html")
        
        try:
            bprice = int(bprice)
            bstock = int(bstock)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 生成圖書編號
            cursor.execute("SELECT COUNT(*) FROM books")
            book_count = cursor.fetchone()[0]
            bid = f"B{book_count + 1:03d}"
            
            cursor.execute("""
            INSERT INTO books (bid, btitle, bauthor, bpublisher, bprice, bstock, total_stock, bcategory)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (bid, btitle, bauthor, bpublisher, bprice, bstock, bstock, bcategory))
            
            conn.commit()
            flash("圖書新增成功")
            return redirect(url_for("admin_books"))
            
        except ValueError:
            flash("價格和庫存必須為數字")
        except sqlite3.Error as e:
            flash(f"新增失敗：{e}")
        finally:
            conn.close()
    
    return render_template("add_book.html")

@app.route("/admin/borrow_records")
@login_required
@admin_required
def admin_borrow_records():
    """管理員借閱記錄管理"""
    status_filter = request.args.get('status', 'all')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
    SELECT br.*, m.username, b.btitle, b.bauthor
    FROM borrow_records br
    JOIN members m ON br.mid = m.mid
    JOIN books b ON br.bid = b.bid
    """
    
    if status_filter == 'borrowed':
        query += " WHERE br.status = 'borrowed'"
    elif status_filter == 'overdue':
        query += " WHERE br.status = 'borrowed' AND br.due_date < date('now')"
    
    query += " ORDER BY br.borrow_date DESC"
    
    records = cursor.execute(query).fetchall()
    conn.close()
    
    return render_template("admin_borrow_records.html", records=records, status_filter=status_filter)

@app.route("/admin/edit_book/<bid>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_book(bid):
    """編輯圖書"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == "GET":
        # 獲取圖書資料
        book = cursor.execute("SELECT * FROM books WHERE bid = ?", (bid,)).fetchone()
        conn.close()
        
        if not book:
            flash("圖書不存在")
            return redirect(url_for("admin_books"))
        
        return render_template("edit_book.html", book=book)
    
    elif request.method == "POST":
        btitle = request.form.get("btitle", "").strip()
        bauthor = request.form.get("bauthor", "").strip()
        bpublisher = request.form.get("bpublisher", "").strip()
        bprice = request.form.get("bprice", "0")
        bstock = request.form.get("bstock", "0")
        total_stock = request.form.get("total_stock", "0")
        bcategory = request.form.get("bcategory", "").strip()
        
        if not btitle or not bauthor:
            flash("請輸入書名和作者")
            book = cursor.execute("SELECT * FROM books WHERE bid = ?", (bid,)).fetchone()
            conn.close()
            return render_template("edit_book.html", book=book)
        
        try:
            bprice = int(bprice)
            bstock = int(bstock)
            total_stock = int(total_stock)
            
            # 檢查庫存邏輯
            if bstock > total_stock:
                flash("目前庫存不能大於總庫存")
                book = cursor.execute("SELECT * FROM books WHERE bid = ?", (bid,)).fetchone()
                conn.close()
                return render_template("edit_book.html", book=book)
            
            # 檢查是否有足夠的庫存可以調整（考慮已借出的圖書）
            current_book = cursor.execute("SELECT * FROM books WHERE bid = ?", (bid,)).fetchone()
            borrowed_count = current_book['total_stock'] - current_book['bstock']
            
            if total_stock < borrowed_count:
                flash(f"總庫存不能少於已借出數量（{borrowed_count}本）")
                conn.close()
                return render_template("edit_book.html", book=current_book)
            
            # 更新圖書資料
            cursor.execute("""
            UPDATE books 
            SET btitle = ?, bauthor = ?, bpublisher = ?, bprice = ?, 
                bstock = ?, total_stock = ?, bcategory = ?
            WHERE bid = ?
            """, (btitle, bauthor, bpublisher, bprice, bstock, total_stock, bcategory, bid))
            
            conn.commit()
            flash("圖書更新成功")
            return redirect(url_for("admin_books"))
            
        except ValueError:
            flash("價格和庫存必須為數字")
        except sqlite3.Error as e:
            flash(f"更新失敗：{e}")
        finally:
            conn.close()
        
        # 如果有錯誤，重新載入編輯頁面
        conn = get_db_connection()
        book = conn.execute("SELECT * FROM books WHERE bid = ?", (bid,)).fetchone()
        conn.close()
        return render_template("edit_book.html", book=book)

@app.route("/admin/delete_book/<bid>", methods=["POST"])
@login_required
@admin_required
def delete_book(bid):
    """刪除圖書"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 檢查是否有借閱記錄
        borrowed_count = cursor.execute("""
        SELECT COUNT(*) FROM borrow_records 
        WHERE bid = ? AND status = 'borrowed'
        """, (bid,)).fetchone()[0]
        
        if borrowed_count > 0:
            flash(f"無法刪除：此圖書目前有 {borrowed_count} 本正在借閱中")
            return redirect(url_for("admin_books"))
        
        # 獲取圖書資訊用於提示
        book = cursor.execute("SELECT btitle FROM books WHERE bid = ?", (bid,)).fetchone()
        
        if not book:
            flash("圖書不存在")
            return redirect(url_for("admin_books"))
        
        # 刪除圖書
        cursor.execute("DELETE FROM books WHERE bid = ?", (bid,))
        conn.commit()
        
        flash(f"成功刪除圖書《{book['btitle']}》")
        
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"刪除失敗：{e}")
    finally:
        conn.close()
    
    return redirect(url_for("admin_books"))

@app.route("/admin/update_stock/<bid>", methods=["POST"])
@login_required
@admin_required
def update_stock(bid):
    """更新庫存"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        current_stock = int(request.form.get("current_stock", "0"))
        total_stock = int(request.form.get("total_stock", "0"))
        
        if current_stock > total_stock:
            flash("目前庫存不能大於總庫存")
            return redirect(url_for("admin_books"))
        
        # 檢查已借出數量
        current_book = cursor.execute("SELECT * FROM books WHERE bid = ?", (bid,)).fetchone()
        borrowed_count = current_book['total_stock'] - current_book['bstock']
        
        if total_stock < borrowed_count:
            flash(f"總庫存不能少於已借出數量（{borrowed_count}本）")
            return redirect(url_for("admin_books"))
        
        # 更新庫存
        cursor.execute("""
        UPDATE books SET bstock = ?, total_stock = ? WHERE bid = ?
        """, (current_stock, total_stock, bid))
        
        conn.commit()
        flash("庫存更新成功")
        
    except ValueError:
        flash("庫存數量必須為數字")
    except sqlite3.Error as e:
        flash(f"更新失敗：{e}")
    finally:
        conn.close()
    
    return redirect(url_for("admin_books"))

# 模板過濾器
@app.template_filter('add_stars')
def add_stars(s: str) -> str:
    """用戶名前後加上星號"""
    return f'★{s.upper()}★'

if __name__ == "__main__":
    # 確保資料庫初始化
    init_db()
    
    # 啟動應用程式
    app.run(debug=True, host='0.0.0.0', port=5000)

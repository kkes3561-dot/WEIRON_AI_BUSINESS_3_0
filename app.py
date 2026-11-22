import os
import sqlite3
import json
import urllib.request
import urllib.error
import requests

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, jsonify, session, redirect

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "weiron.db")
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "").strip()
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
DEEPSEEK_MODEL_FAST = os.environ.get("DEEPSEEK_MODEL_FAST", "deepseek-flash").strip()
DEEPSEEK_MODEL_HEAVY = os.environ.get("DEEPSEEK_MODEL_HEAVY", "deepseek-v4-pro").strip()
DEEPSEEK_TIMEOUT = int(os.environ.get("DEEPSEEK_TIMEOUT", "90"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "local-dev-key-change-before-public-deployment"
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS companies(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          industry TEXT DEFAULT '', description TEXT DEFAULT '',
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL,
          email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'admin', created_at TEXT NOT NULL,
          FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS customers(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL,
          name TEXT NOT NULL, phone TEXT DEFAULT '', email TEXT DEFAULT '',
          company_name TEXT DEFAULT '', source TEXT DEFAULT '',
          status TEXT NOT NULL DEFAULT 'Новый', notes TEXT DEFAULT '',
          created_at TEXT NOT NULL,
          FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS deals(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL,
          customer_id INTEGER, title TEXT NOT NULL, amount REAL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'Новая', expected_close TEXT DEFAULT '',
          notes TEXT DEFAULT '', created_at TEXT NOT NULL,
          FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE,
          FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS tasks(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL,
          customer_id INTEGER, deal_id INTEGER, title TEXT NOT NULL,
          due_date TEXT DEFAULT '', priority TEXT DEFAULT 'Обычный',
          status TEXT NOT NULL DEFAULT 'Открыта', created_at TEXT NOT NULL,
          FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE,
          FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE SET NULL,
          FOREIGN KEY(deal_id) REFERENCES deals(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS knowledge(
          id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL,
          title TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL,
          FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_customers_company ON customers(company_id);
        CREATE INDEX IF NOT EXISTS idx_deals_company ON deals(company_id);
        CREATE INDEX IF NOT EXISTS idx_tasks_company ON tasks(company_id);
        CREATE INDEX IF NOT EXISTS idx_knowledge_company ON knowledge(company_id);
        """)

def current_company_id():
    return session.get("company_id")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id") or not current_company_id():
            return jsonify(error="Сессия завершена. Войдите снова."), 401
        return fn(*args, **kwargs)
    return wrapper

def company():
    with db() as c:
        row = c.execute("SELECT * FROM companies WHERE id=?", (current_company_id(),)).fetchone()
    return dict(row) if row else {}

@app.route("/")
def home():
    return redirect("/app") if session.get("user_id") else render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    data = request.get_json(silent=True) or request.form
    name = str(data.get("company", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    industry = str(data.get("industry", "")).strip()
    if not name or not email or len(password) < 10:
        msg = "Укажите компанию, email и пароль не короче 10 символов."
        if request.is_json: return jsonify(error=msg), 400
        return render_template("register.html", error=msg)
    try:
        with db() as c:
            cur = c.execute("INSERT INTO companies(name,industry,created_at) VALUES(?,?,?)",
                            (name, industry, now()))
            cid = cur.lastrowid
            cur = c.execute("INSERT INTO users(company_id,email,password_hash,created_at) VALUES(?,?,?,?)",
                            (cid, email, generate_password_hash(password), now()))
            uid = cur.lastrowid
        session.clear()
        session.update(user_id=uid, company_id=cid, email=email)
        if request.is_json: return jsonify(ok=True, redirect="/app")
        return redirect("/app")
    except sqlite3.IntegrityError:
        msg = "Этот email уже зарегистрирован."
        if request.is_json: return jsonify(error=msg), 409
        return render_template("register.html", error=msg)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    data = request.get_json(silent=True) or request.form
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if user and check_password_hash(user["password_hash"], password):
        session.clear()
        session.update(user_id=user["id"], company_id=user["company_id"], email=user["email"])
        if request.is_json: return jsonify(ok=True, redirect="/app")
        return redirect("/app")
    msg = "Неверный email или пароль."
    if request.is_json: return jsonify(error=msg), 401
    return render_template("login.html", error=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/app")
@login_required
def workspace():
    return render_template("app.html", email=session.get("email", ""))

@app.route("/api/overview")
@login_required
def overview():
    cid = current_company_id()
    with db() as c:
        customers = c.execute("SELECT COUNT(*) FROM customers WHERE company_id=?", (cid,)).fetchone()[0]
        new_customers = c.execute("SELECT COUNT(*) FROM customers WHERE company_id=? AND status='Новый'", (cid,)).fetchone()[0]
        deals = c.execute("SELECT COUNT(*) FROM deals WHERE company_id=?", (cid,)).fetchone()[0]
        pipeline = c.execute("SELECT COALESCE(SUM(amount),0) FROM deals WHERE company_id=? AND status NOT IN ('Успешно','Провалена')", (cid,)).fetchone()[0]
        tasks = c.execute("SELECT COUNT(*) FROM tasks WHERE company_id=? AND status!='Выполнена'", (cid,)).fetchone()[0]
        recent = [dict(x) for x in c.execute("SELECT id,name,phone,email,status,created_at FROM customers WHERE company_id=? ORDER BY id DESC LIMIT 7", (cid,))]
    return jsonify(company=company(), customers=customers, new_customers=new_customers,
                   deals=deals, pipeline=pipeline, tasks=tasks, recent=recent)

@app.route("/api/customers", methods=["GET", "POST"])
@login_required
def customers_api():
    cid = current_company_id()
    if request.method == "POST":
        d = request.get_json(silent=True) or {}
        name = str(d.get("name", "")).strip()
        if not name: return jsonify(error="Укажите имя клиента."), 400
        with db() as c:
            cur = c.execute("""INSERT INTO customers(company_id,name,phone,email,company_name,source,status,notes,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (cid, name, str(d.get("phone","")).strip(), str(d.get("email","")).strip(),
                 str(d.get("company_name","")).strip(), str(d.get("source","")).strip(),
                 str(d.get("status","Новый")), str(d.get("notes","")).strip(), now()))
            return jsonify(ok=True, id=cur.lastrowid)
    with db() as c:
        rows = [dict(x) for x in c.execute("SELECT * FROM customers WHERE company_id=? ORDER BY id DESC", (cid,))]
    return jsonify(rows)

@app.route("/api/customers/<int:item_id>", methods=["PATCH", "DELETE"])
@login_required
def customer_item(item_id):
    cid = current_company_id()
    with db() as c:
        row = c.execute("SELECT id FROM customers WHERE id=? AND company_id=?", (item_id,cid)).fetchone()
        if not row: return jsonify(error="Клиент не найден."), 404
        if request.method == "DELETE":
            c.execute("DELETE FROM customers WHERE id=? AND company_id=?", (item_id,cid))
            return jsonify(ok=True)
        d = request.get_json(silent=True) or {}
        allowed = {"name","phone","email","company_name","source","status","notes"}
        fields = {k: str(v).strip() for k,v in d.items() if k in allowed}
        if not fields: return jsonify(error="Нет данных для изменения."), 400
        sql = ", ".join(f"{k}=?" for k in fields)
        c.execute(f"UPDATE customers SET {sql} WHERE id=? AND company_id=?", (*fields.values(),item_id,cid))
    return jsonify(ok=True)

@app.route("/api/deals", methods=["GET", "POST"])
@login_required
def deals_api():
    cid = current_company_id()
    if request.method == "POST":
        d = request.get_json(silent=True) or {}
        title = str(d.get("title","")).strip()
        if not title: return jsonify(error="Укажите название сделки."), 400
        customer_id = d.get("customer_id") or None
        with db() as c:
            if customer_id and not c.execute("SELECT id FROM customers WHERE id=? AND company_id=?", (customer_id,cid)).fetchone():
                return jsonify(error="Выбранный клиент не найден."), 400
            cur = c.execute("""INSERT INTO deals(company_id,customer_id,title,amount,status,expected_close,notes,created_at)
              VALUES(?,?,?,?,?,?,?,?)""", (cid,customer_id,title,float(d.get("amount") or 0),
              str(d.get("status","Новая")),str(d.get("expected_close","")),str(d.get("notes","")),now()))
            return jsonify(ok=True,id=cur.lastrowid)
    with db() as c:
        rows = [dict(x) for x in c.execute("""SELECT d.*,c.name customer_name FROM deals d
          LEFT JOIN customers c ON c.id=d.customer_id AND c.company_id=d.company_id
          WHERE d.company_id=? ORDER BY d.id DESC""",(cid,))]
    return jsonify(rows)

@app.route("/api/deals/<int:item_id>", methods=["PATCH", "DELETE"])
@login_required
def deal_item(item_id):
    cid = current_company_id()
    with db() as c:
        row = c.execute("SELECT id FROM deals WHERE id=? AND company_id=?", (item_id,cid)).fetchone()
        if not row: return jsonify(error="Сделка не найдена."),404
        if request.method == "DELETE":
            c.execute("DELETE FROM deals WHERE id=? AND company_id=?", (item_id,cid)); return jsonify(ok=True)
        d = request.get_json(silent=True) or {}
        allowed={"title","amount","status","expected_close","notes","customer_id"}
        fields={k:v for k,v in d.items() if k in allowed}
        if "customer_id" in fields and fields["customer_id"]:
            if not c.execute("SELECT id FROM customers WHERE id=? AND company_id=?", (fields["customer_id"],cid)).fetchone():
                return jsonify(error="Клиент не найден."),400
        if not fields:return jsonify(error="Нет данных для изменения."),400
        sql=", ".join(f"{k}=?" for k in fields)
        c.execute(f"UPDATE deals SET {sql} WHERE id=? AND company_id=?",(*fields.values(),item_id,cid))
    return jsonify(ok=True)

@app.route("/api/tasks", methods=["GET", "POST"])
@login_required
def tasks_api():
    cid=current_company_id()
    if request.method=="POST":
        d=request.get_json(silent=True) or {}; title=str(d.get("title","")).strip()
        if not title:return jsonify(error="Укажите задачу."),400
        customer_id=d.get("customer_id") or None
        with db() as c:
            if customer_id and not c.execute("SELECT id FROM customers WHERE id=? AND company_id=?",(customer_id,cid)).fetchone():
                return jsonify(error="Клиент не найден."),400
            cur=c.execute("""INSERT INTO tasks(company_id,customer_id,title,due_date,priority,status,created_at)
              VALUES(?,?,?,?,?,?,?)""",(cid,customer_id,title,str(d.get("due_date","")),
              str(d.get("priority","Обычный")),str(d.get("status","Открыта")),now()))
            return jsonify(ok=True,id=cur.lastrowid)
    with db() as c:
        rows=[dict(x) for x in c.execute("""SELECT t.*,c.name customer_name FROM tasks t
          LEFT JOIN customers c ON c.id=t.customer_id AND c.company_id=t.company_id
          WHERE t.company_id=? ORDER BY CASE WHEN t.status='Выполнена' THEN 1 ELSE 0 END,t.due_date,t.id DESC""",(cid,))]
    return jsonify(rows)

@app.route("/api/tasks/<int:item_id>", methods=["PATCH","DELETE"])
@login_required
def task_item(item_id):
    cid=current_company_id()
    with db() as c:
        if not c.execute("SELECT id FROM tasks WHERE id=? AND company_id=?",(item_id,cid)).fetchone():
            return jsonify(error="Задача не найдена."),404
        if request.method=="DELETE":
            c.execute("DELETE FROM tasks WHERE id=? AND company_id=?",(item_id,cid)); return jsonify(ok=True)
        d=request.get_json(silent=True) or {}
        allowed={"title","due_date","priority","status","customer_id"}
        fields={k:v for k,v in d.items() if k in allowed}
        if not fields:return jsonify(error="Нет данных для изменения."),400
        sql=", ".join(f"{k}=?" for k in fields)
        c.execute(f"UPDATE tasks SET {sql} WHERE id=? AND company_id=?",(*fields.values(),item_id,cid))
    return jsonify(ok=True)

@app.route("/api/knowledge", methods=["GET","POST"])
@login_required
def knowledge_api():
    cid=current_company_id()
    if request.method=="POST":
        d=request.get_json(silent=True) or {}; title=str(d.get("title","")).strip(); body=str(d.get("body","")).strip()
        if not title or not body:return jsonify(error="Заполните название и текст материала."),400
        with db() as c:c.execute("INSERT INTO knowledge(company_id,title,body,created_at) VALUES(?,?,?,?)",(cid,title,body,now()))
        return jsonify(ok=True)
    with db() as c: rows=[dict(x) for x in c.execute("SELECT * FROM knowledge WHERE company_id=? ORDER BY id DESC",(cid,))]
    return jsonify(rows)

@app.route("/api/knowledge/<int:item_id>",methods=["DELETE"])
@login_required
def knowledge_item(item_id):
    with db() as c:c.execute("DELETE FROM knowledge WHERE id=? AND company_id=?",(item_id,current_company_id()))
    return jsonify(ok=True)

@app.route("/api/settings",methods=["GET","POST"])
@login_required
def settings_api():
    if request.method=="POST":
        d=request.get_json(silent=True) or {}
        with db() as c:
            c.execute("UPDATE companies SET name=?,industry=?,description=? WHERE id=?",
              (str(d.get("name","")).strip(),str(d.get("industry","")).strip(),
               str(d.get("description","")).strip(),current_company_id()))
        return jsonify(ok=True)
    return jsonify(company())

@app.route("/api/ai/status")
@login_required
def ai_status():
    if not DEEPSEEK_API_KEY:
        return jsonify(ok=False, connected=False, provider="DeepSeek", error="Не задан DEEPSEEK_API_KEY в .env"), 503
    try:
        response = requests.get(
            f"{DEEPSEEK_BASE_URL}/models",
            headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
            timeout=min(DEEPSEEK_TIMEOUT, 15),
        )
        if response.status_code >= 400:
            return jsonify(ok=False, connected=False, provider="DeepSeek",
                           error=f"DeepSeek API вернул HTTP {response.status_code}"), 503
        data = response.json()
        models = [item.get("id", "") for item in data.get("data", []) if isinstance(item, dict)]
        return jsonify(ok=True, connected=True, provider="DeepSeek",
                       model_fast=DEEPSEEK_MODEL_FAST, model_heavy=DEEPSEEK_MODEL_HEAVY,
                       available_models=models)
    except requests.RequestException as exc:
        return jsonify(ok=False, connected=False, provider="DeepSeek",
                       error=f"Ошибка подключения: {type(exc).__name__}"), 503
    except (ValueError, TypeError):
        return jsonify(ok=False, connected=False, provider="DeepSeek", error="Некорректный ответ API"), 503

@app.route("/api/ai",methods=["POST"])
@login_required
def ai_api():
    d=request.get_json(silent=True) or {}
    prompt=str(d.get("prompt","")).strip()
    if not prompt:return jsonify(error="Напишите запрос."),400
    if not DEEPSEEK_API_KEY:
        return jsonify(error="Не задан DEEPSEEK_API_KEY. Проверьте файл .env."),503
    cid=current_company_id()
    with db() as c:
        kb="\n".join(f"{r['title']}: {r['body']}" for r in c.execute(
            "SELECT title,body FROM knowledge WHERE company_id=? ORDER BY id DESC LIMIT 15",(cid,)))
        customers=[dict(r) for r in c.execute(
            "SELECT name,phone,email,company_name,status,notes FROM customers WHERE company_id=? ORDER BY id DESC LIMIT 30",(cid,))]
        deals=[dict(r) for r in c.execute(
            "SELECT title,amount,status,expected_close FROM deals WHERE company_id=? ORDER BY id DESC LIMIT 20",(cid,))]
    co=company()
    system=("Ты — AI-помощник WEIRON CRM. Отвечай по-русски, ясно и профессионально. "
      "Используй контекст компании, клиентов, сделок и базы знаний. Не выдумывай факты, цены, контакты и действия. "
      "Если данных недостаточно — прямо скажи об этом. Для сложных запросов дай структурированный анализ и конкретный план действий.\n"
      f"Компания: {co.get('name','')}. Сфера: {co.get('industry','')}. Описание: {co.get('description','')}.\n"
      f"База знаний:\n{kb or 'Не заполнена'}\n"
      f"Клиенты CRM (последние 30): {json.dumps(customers,ensure_ascii=False)}\n"
      f"Сделки CRM (последние 20): {json.dumps(deals,ensure_ascii=False)}")
    prompt_lower=prompt.lower()
    deep_terms=("проанализируй", "стратег", "сравни", "исследуй", "архитект", "разработ", "отлад", "подробно", "план внедрения", "оптимизируй")
    is_deep=any(term in prompt_lower for term in deep_terms) or len(prompt)>1200
    model=DEEPSEEK_MODEL_HEAVY if is_deep else DEEPSEEK_MODEL_FAST
    payload={"model":model,"messages":[
        {"role":"system","content":system},{"role":"user","content":prompt}],
        "stream":False,"temperature":0.2}
    try:
        response=requests.post(
            f"{DEEPSEEK_BASE_URL}/chat/completions",
            headers={"Authorization":f"Bearer {DEEPSEEK_API_KEY}","Content-Type":"application/json"},
            json=payload, timeout=DEEPSEEK_TIMEOUT)
        if response.status_code >= 400:
            return jsonify(error=f"DeepSeek API вернул HTTP {response.status_code}.",
                           detail="Проверьте доступность выбранной модели и баланс API."),502
        result=response.json()
        choices=result.get("choices") or []
        answer=str(((choices[0].get("message") or {}).get("content")) if choices else "").strip()
        if not answer: raise RuntimeError("DeepSeek вернул пустой ответ.")
        return jsonify(ok=True,answer=answer,model=model,provider="DeepSeek",mode="глубокий" if is_deep else "быстрый")
    except requests.Timeout:
        return jsonify(error="DeepSeek не ответил вовремя. Повторите запрос."),504
    except requests.RequestException as exc:
        return jsonify(error="Не удалось подключиться к DeepSeek API.",detail=type(exc).__name__),503
    except (ValueError, KeyError, TypeError, RuntimeError):
        return jsonify(error="Не удалось обработать ответ DeepSeek API."),502

@app.route("/health")
def health():
    return jsonify(status="ok",app="WEIRON AI BUSINESS 3.0")

init_db()
if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)

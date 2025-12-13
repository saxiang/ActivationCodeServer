# 新增Base64和解密相关依赖
import base64
from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse  # 新增：统一JSON响应，强制UTF-8
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

import bcrypt
import datetime
import uuid

# ---------------------- 数据库配置（修复：删除无效的encoding参数） ----------------------
# 保留charset=utf8确保SQLite读写中文UTF-8编码，删除create_engine的encoding参数
SQLALCHEMY_DATABASE_URL = "sqlite:///./db.sqlite3?charset=utf8"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}  # 仅保留SQLite必需参数
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AdminUser(Base):  # 新增：管理员表模型
    __tablename__ = "admin_users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

# 激活码表（保留原有字段，激活码为自定义加密码）
class ActivationCode(Base):
    __tablename__ = "activation_codes"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True)  # 存储最终加密后的激活码
    raw_data = Column(String)  # 存储原始拼接字符串（产品编号+手机号），方便解密
    is_activated = Column(Boolean, default=False)
    activate_time = Column(DateTime, nullable=True)
    # 核心修改：datetime默认值强制UTC+8，格式化避免乱码
    create_time = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

Base.metadata.create_all(bind=engine)

# ---------------------- 工具函数（新增：统一响应函数，强制UTF-8） ----------------------
def utf8_response(data: dict):
    """统一返回UTF-8编码的JSON响应，解决iOS中文乱码"""
    return JSONResponse(
        content=data,
        headers={
            "Content-Type": "application/json; charset=utf-8",  # 强制指定UTF-8
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Origin": "*"  # 兜底跨域头
        }
    )

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 后端加密函数（和前端保持一致，双重验证）
def encrypt_code(product_id: str, phone: str) -> str:
    # 1. 拼接原始字符串
    raw_str = product_id + phone
    # 2. 第一层Base64编码
    first_b64 = base64.b64encode(raw_str.encode("utf-8")).decode("utf-8")
    # 3. 加盐（尾部加9527）
    salted_str = first_b64 + "9527"
    # 4. 第二层Base64编码
    final_code = base64.b64encode(salted_str.encode("utf-8")).decode("utf-8")
    return final_code, raw_str

# 后端解密函数
def decrypt_code(encrypt_code: str) -> tuple:
    try:
        # 1. 解第二层Base64
        second_decode = base64.b64decode(encrypt_code.encode("utf-8")).decode("utf-8")
        # 2. 去盐（去掉尾部9527）
        if not second_decode.endswith("9527"):
            raise ValueError("激活码格式错误（无加盐标识）")
        first_b64 = second_decode[:-4]  # 9527是4位，截取前面部分
        # 3. 解第一层Base64
        raw_str = base64.b64decode(first_b64.encode("utf-8")).decode("utf-8")
        # 4. 拆分：前3位=产品编号，剩余=手机号
        if len(raw_str) < 3:
            raise ValueError("激活码解析失败（原始数据过短）")
        product_id = raw_str[:3]
        phone = raw_str[3:]
        return product_id, phone
    except Exception as e:
        raise ValueError(f"解密失败：{str(e)}")

# ---------------------- FastAPI + 跨域配置（强化UTF-8兼容） ----------------------
app = FastAPI(title="激活码管理系统", docs_url="/docs")

origins = [
    "https://3guys.com.cn",       # 后端域名
    "https://login.3guys.com.cn", # 前端登录页域名
    "http://localhost:8080",      # 本地开发环境（可选）
    "http://192.168.3.111:8080"       # 本地开发环境（可选）
]

# 修复CORS：确保覆盖所有源、方法、头，且中间件优先加载
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,                # 显式指定允许的源（替代通配符，解决浏览器兼容）
    allow_credentials=True,              # 允许携带 Cookie/token
    allow_methods=["*"],                 # 允许所有请求方法（GET/POST/OPTIONS 等）
    allow_headers=["*"],                 # 允许所有请求头
    expose_headers=["*"],                # 暴露所有响应头
    max_age=3600                         # 预检请求缓存时间（减少 OPTIONS 请求次数）
)

# 在CORS配置后新增：处理所有OPTIONS预检请求，返回UTF-8编码
@app.options("/{path:path}")
async def handle_options(path: str):
    return utf8_response({"status": "ok"})

# ---------------------- 核心接口（全部替换为utf8_response，强制UTF-8） ----------------------
# 初始化管理员账号
@app.get("/init_admin")
def init_admin(db: Session = Depends(get_db)):
    def hash_password(pwd):
        return bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")  # 强制UTF-8
    
    # 定义要创建的管理员账号列表（便于维护）
    admin_users = [
        ("chen", "chen123456"),
        ("alanwong", "alan123456"),
        ("zengyanbin", "zeng123456")
    ]
    
    try:
        # 循环插入每个管理员账号（一次execute执行一条，语法正确）
        for username, password in admin_users:
            db.execute(
                text("INSERT INTO admin_users (username, password_hash) VALUES (:un, :pwd)"),
                {"un": username, "pwd": hash_password(password)}
            )
        db.commit()
        return utf8_response({"msg": "管理员账号创建成功! 账号：c/a/z"})
    except Exception as e:  # 替换IntegrityError为通用异常（简化）
        return utf8_response({"msg": f"管理员账号已存在或创建失败：{str(e)}"})

# 修复login接口
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # 修复：execute + text()
    user = db.execute(
        text("SELECT * FROM admin_users WHERE username = :un"),
        {"un": username}
    ).first()
    if not user:
        return utf8_response({"detail": "账号不存在"}), 401  # 统一UTF-8响应
    if not bcrypt.checkpw(password.encode("utf-8"), user[2].encode("utf-8")):
        return utf8_response({"detail": "密码错误"}), 401
    return utf8_response({"access_token": username, "token_type": "bearer"})

# 生成激活码接口（自定义加密逻辑）
@app.post("/generate_codes")
def generate_codes(product_id: str = Form(...), phone: str = Form(...), db: Session = Depends(get_db)):
    # 校验产品编号（3位数字）
    if not product_id.isdigit() or len(product_id) != 3:
        return utf8_response({"detail": "产品编号必须为3位数字"}), 400
    # 校验手机号（11位数字）
    if not phone.isdigit() or len(phone) != 11:
        return utf8_response({"detail": "手机号码必须为11位数字"}), 400
    
    # 生成加密激活码
    final_code, raw_str = encrypt_code(product_id, phone)
    
    # 修复：原生SQL查询用execute + text()（原错误行）
    exist = db.execute(
        text("SELECT 1 FROM activation_codes WHERE code = :c"),  # text包裹SQL
        {"c": final_code}
    ).first()
    if exist:
        return utf8_response({"detail": "该激活码已存在"}), 400
    
    # 修复：插入数据也用execute + text()，时间格式化避免乱码
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        text("""
            INSERT INTO activation_codes (code, raw_data, is_activated, create_time)
            VALUES (:code, :raw, 0, :ct)
        """),
        {
            "code": final_code,
            "raw": raw_str,
            "ct": current_time
        }
    )
    db.commit()
    return utf8_response({"code": final_code, "msg": "激活码生成成功"})

# 解密激活码接口
@app.post("/decrypt_code")
def decrypt_code_api(code: str = Form(...)):
    try:
        product_id, phone = decrypt_code(code)
        return utf8_response({"product_id": product_id, "phone": phone, "msg": "解密成功"})
    except ValueError as e:
        return utf8_response({"detail": str(e)}), 400

# 3. 验证激活码接口（iOS App调用）
@app.get("/verify_code")
def verify_code(code: str, db: Session = Depends(get_db)):
    ac = db.query(ActivationCode).filter(ActivationCode.code == code).first()
    if not ac:
        return utf8_response({"status": False, "msg": "激活码不存在"})
    if ac.is_activated:
        return utf8_response({"status": False, "msg": "激活码已使用"})
    return utf8_response({"status": True, "msg": "激活码有效"})

# 4. 激活激活码接口（兼容GET/POST，UTF-8响应）
@app.api_route("/activate_code", methods=["GET", "POST"])
def activate_code(code: str, db: Session = Depends(get_db)):
    ac = db.query(ActivationCode).filter(ActivationCode.code == code).first()
    if not ac:
        return utf8_response({"detail": "激活码不存在"}), 404
    if ac.is_activated:
        return utf8_response({"detail": "激活码已激活"}), 400
    # 标记为已激活，时间强制UTC+8
    ac.is_activated = True
    ac.activate_time = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(ac)
    return utf8_response({"status": True, "msg": "激活成功"})

# 5.重置激活状态接口
@app.post("/reset_activation")  
def reset_activation(code: str = Form(...), db: Session = Depends(get_db)):
    # 1. 根据激活码字符串查询
    activation_code = db.query(ActivationCode).filter(ActivationCode.code == code).first()
    if not activation_code:
        return utf8_response({"detail": "激活码不存在"}), 400
    
    # 2. 校验是否为已激活状态
    if not activation_code.is_activated:
        return utf8_response({"detail": "该激活码已是未激活状态，无需重置"}), 400
    
    # 3. 重置状态：未激活 + 清空激活时间
    activation_code.is_activated = False
    activation_code.activate_time = None
    db.commit()
    db.refresh(activation_code)
    
    return utf8_response({"msg": f"激活码【{code}】已重置为未激活状态", "code": code})

# 6.删除激活码接口
@app.post("/delete_code")
def delete_code(code: str = Form(...), db: Session = Depends(get_db)):
    # 1. 校验激活码是否存在
    activation_code = db.query(ActivationCode).filter(ActivationCode.code == code).first()
    if not activation_code:
        return utf8_response({"detail": "激活码不存在"}), 400
    
    # 2. 可选：禁止删除已激活的激活码（根据业务需求调整，如需允许则注释此行）
    if activation_code.is_activated:
        return utf8_response({"detail": "禁止删除已激活的激活码"}), 400
    
    # 3. 删除激活码
    db.delete(activation_code)
    db.commit()
    
    return utf8_response({"msg": f"激活码【{code}】已成功删除"})

# 获取激活码列表（修复时间格式化乱码）
@app.get("/get_codes")
def get_codes(page: int = 1, size: int = 20, db: Session = Depends(get_db)):
    # 修复：总数量查询
    total = db.execute(text("SELECT COUNT(*) FROM activation_codes")).scalar()
    # 修复：分页数据查询
    codes = db.execute(
        text("""
            SELECT id, code, raw_data, is_activated, activate_time, create_time
            FROM activation_codes
            LIMIT :size OFFSET :offset
        """),
        {"size": size, "offset": (page-1)*size}
    ).fetchall()
    # 格式化返回（修复时间字段编码/空值问题）
    data = []
    for c in codes:
        # 时间字段格式化，空值转为空字符串，避免编码异常
        activate_time = c[4].strftime("%Y-%m-%d %H:%M:%S") if c[4] else ""
        create_time = c[5].strftime("%Y-%m-%d %H:%M:%S") if c[5] else ""
        data.append({
            "id": c[0],
            "code": c[1],
            "raw_data": c[2] or "",
            "is_activated": bool(c[3]),
            "activate_time": activate_time,
            "create_time": create_time
        })
    return utf8_response({"total": total, "list": data})

# 退出登录（空接口，前端处理）
@app.get("/logout")
def logout():
    return utf8_response({"msg": "退出成功"})
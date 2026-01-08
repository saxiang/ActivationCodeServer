# 新增Base64和解密相关依赖
import base64
from fastapi import FastAPI, HTTPException, Depends, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

import bcrypt
import datetime
import uuid

# PostgreSQL兼容的时区处理（可选，避免时间差）
from sqlalchemy.sql import func
from sqlalchemy.exc import SQLAlchemyError  # 新增：捕获数据库异常
import os

# 时间格式化工具函数：兼容字符串/DateTime/None
def format_datetime(dt):
    if dt is None:
        return ""
    # 如果是字符串，直接返回（不管格式，避免依赖re）
    if isinstance(dt, str):
        return dt if dt.strip() else ""
    # 如果是DateTime对象，格式化
    if isinstance(dt, datetime.datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    # 其他类型，返回空
    return ""

# ---------------------- 数据库配置 ----------------------
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# 本地开发兜底
if not SQLALCHEMY_DATABASE_URL:
    SQLALCHEMY_DATABASE_URL = "postgresql://neondb_owner:npg_vBNF4s5myUuE@ep-curly-wind-a1fnfd0a-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require" 

# 兜底校验
if not SQLALCHEMY_DATABASE_URL:
    raise ValueError("DATABASE_URL未配置！本地请检查硬编码URL，Render请检查环境变量")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True  # 防止连接超时
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AdminUser(Base):  # 管理员表模型
    __tablename__ = "admin_users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

# 激活码表（含查询次数字段）
class ActivationCode(Base):
    __tablename__ = "activation_codes"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(255), unique=True, index=True) 
    raw_data = Column(String(255))
    is_activated = Column(Boolean, default=False)
    activate_time = Column(DateTime, nullable=True)
    create_time = Column(DateTime, default=func.now())
    query_count = Column(Integer, default=0, nullable=False, index=True)  # 查询次数

class ProductInfo(Base):
    __tablename__ = "product_info" 
    id = Column(Integer, primary_key=True, index=True)
    guide_link = Column(String(512), nullable=True)
    feishu_link = Column(String(512), nullable=True)
    shortcut_link = Column(String(512), nullable=True)

Base.metadata.create_all(bind=engine)

# ---------------------- 统一响应函数（强制UTF-8+跨域） ----------------------
def utf8_response(data: dict, status_code: int = 200):
    response_data = data.copy()
    response_data["code"] = status_code  # 自动注入code字段
    return JSONResponse(
        content=response_data,
        status_code=status_code, 
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Origin": "*"
        }
    )

# 数据库会话依赖
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 后端加密函数
def encrypt_code(product_id: str, phone: str) -> tuple:
    raw_str = product_id + phone
    first_b64 = base64.b64encode(raw_str.encode("utf-8")).decode("utf-8")
    salted_str = first_b64 + "9527"
    final_code = base64.b64encode(salted_str.encode("utf-8")).decode("utf-8")
    return final_code, raw_str

# 后端解密函数
def decrypt_code(encrypt_code: str) -> tuple:
    try:
        second_decode = base64.b64decode(encrypt_code.encode("utf-8")).decode("utf-8")
        if not second_decode.endswith("9527"):
            raise ValueError("激活码格式错误（无加盐标识）")
        first_b64 = second_decode[:-4]
        raw_str = base64.b64decode(first_b64.encode("utf-8")).decode("utf-8")
        if len(raw_str) < 3:
            raise ValueError("激活码解析失败（原始数据过短）")
        product_id = raw_str[:3]
        phone = raw_str[3:]
        return product_id, phone
    except Exception as e:
        raise ValueError(f"解密失败：{str(e)}")

# ---------------------- FastAPI 初始化 + 跨域配置 ----------------------
app = FastAPI(
    title="激活码管理系统",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

origins = [
    "https://3guys.com.cn",
    "https://login.3guys.com.cn",
    "https://getlink.3guys.com.cn",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://192.168.3.111:8080"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600
)

# 处理OPTIONS预检请求
@app.options("/{path:path}")
async def handle_options(path: str):
    return utf8_response({"status": "ok"})

# ---------------------- 核心接口（统一格式，修复文档生成问题） ----------------------
# 初始化管理员账号
@app.get("/init_admin")
def init_admin(db: Session = Depends(get_db)):
    def hash_password(pwd):
        return bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    admin_users = [
        ("chen", "chen123456"),
        ("alanwong", "alan123456"),
        ("zengyanbin", "zeng123456")
    ]
    
    try:
        for username, password in admin_users:
            db.execute(
                text("INSERT INTO admin_users (username, password_hash) VALUES (:un, :pwd)"),
                {"un": username, "pwd": hash_password(password)}
            )
        db.commit()
        return utf8_response({"msg": "管理员账号创建成功! 账号：c/a/z"})
    except Exception as e: 
        return utf8_response({"msg": f"管理员账号已存在或创建失败：{str(e)}"}, status_code=400)

# 登录接口（添加Request参数）
@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.form()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
    except:
        try:
            data = await request.json()
            username = data.get("username", "").strip()
            password = data.get("password", "").strip()
        except:
            return utf8_response({"msg": "参数格式错误（仅支持Form/JSON）"}, status_code=401)
    
    if not username or not password:
        return utf8_response({"msg": "账号/密码不能为空"}, status_code=401)
    
    user = db.execute(
        text("SELECT id, username, password_hash FROM admin_users WHERE username = :un"),
        {"un": username}
    ).first()
    if not user:
        return utf8_response({"msg": "账号不存在"}, status_code=401)
    
    password_hash = user[2]
    if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
        return utf8_response({"msg": "密码错误"}, status_code=401)
    
    return utf8_response({"access_token": username, "token_type": "bearer"}, status_code=200)

# 生成激活码接口（添加Request参数）
@app.post("/generate_codes")
def generate_codes(
    request: Request,
    product_id: str = Form(...), 
    phone: str = Form(...), 
    db: Session = Depends(get_db)
):
    if not product_id.isdigit() or len(product_id) != 3:
        return utf8_response({"msg": "产品编号必须为3位数字"}, status_code=400)
    if not phone.isdigit() or len(phone) != 11:
        return utf8_response({"msg": "手机号码必须为11位数字"}, status_code=400)
    
    final_code, raw_str = encrypt_code(product_id, phone)
    
    exist = db.execute(
        text("SELECT 1 FROM activation_codes WHERE code = :c"),
        {"c": final_code}
    ).first()
    if exist:
        return utf8_response({"msg": "该激活码已存在"}, status_code=400)
    
    beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
    current_beijing_time = datetime.datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        text("""
            INSERT INTO activation_codes (code, raw_data, is_activated, create_time)
            VALUES (:code, :raw, false, :ct)
        """),
        {"code": final_code, "raw": raw_str, "ct": current_beijing_time}
    )
    db.commit()
    return utf8_response({"actcode": final_code, "msg": "激活码生成成功"})

# 解密激活码接口（添加Request参数）
@app.post("/decrypt_code")
def decrypt_code_api(request: Request, code: str = Form(...)):
    try:
        product_id, phone = decrypt_code(code)
        return utf8_response({"product_id": product_id, "phone": phone, "msg": "解密成功"})
    except ValueError as e:
        return utf8_response({"msg": str(e)}, status_code=400)

# iOS App验证激活码接口
@app.get("/verify_code")
def verify_code(code: str, db: Session = Depends(get_db)):
    ac = db.query(ActivationCode).filter(ActivationCode.code == code).first()
    if not ac:
        return utf8_response({"status": "no", "msg": "激活码不存在"}, status_code=404)
    if ac.is_activated:
        return utf8_response({"status": "no", "msg": "激活码已使用"}, status_code=400)
    return utf8_response({"status": "ok", "msg": "激活码有效"})

# 验证激活码接口（最终版：添加Request，统一utf8_response，修复文档问题）
@app.post("/verify_actcode", summary="验证激活码有效性")
def verify_actcode(
    request: Request,
    actcode: str = Form(..., description="32位激活码"), 
    db: Session = Depends(get_db)
):
    try:
        actcode = actcode.strip()
        if not actcode:
            return utf8_response({
                "msg": "激活码不能为空",
                "query_count": 0,
                "remaining_count": 3,
                "is_valid": False
            }, status_code=400)
        
        if len(actcode) != 32:
            return utf8_response({
                "msg": "激活码长度必须为32位",
                "query_count": 0,
                "remaining_count": 3,
                "is_valid": False
            }, status_code=400)
        
        ac = db.query(ActivationCode).filter(ActivationCode.code == actcode).first()
        
        if not ac:
            return utf8_response({
                "msg": "激活码不存在",
                "query_count": 0,
                "remaining_count": 3,
                "is_valid": False
            }, status_code=200)
        
        if ac.query_count >= 3:
            return utf8_response({
                "msg": "该激活码查询次数已用尽（最多3次）",
                "query_count": 3,
                "remaining_count": 0,
                "is_valid": False
            }, status_code=403)
        
        ac.query_count += 1
        db.commit()
        db.refresh(ac)
        
        return utf8_response({
            "msg": "激活码验证成功",
            "query_count": ac.query_count,
            "remaining_count": 3 - ac.query_count,
            "is_valid": True
        }, status_code=200)
    
    except SQLAlchemyError as e:
        db.rollback()
        return utf8_response({
            "msg": f"数据库操作失败：{str(e)}",
            "query_count": 0,
            "remaining_count": 3,
            "is_valid": False
        }, status_code=500)

# 激活激活码接口
@app.api_route("/activate_code", methods=["GET", "POST"])
def activate_code(code: str, db: Session = Depends(get_db)):
    ac = db.query(ActivationCode).filter(ActivationCode.code == code).first()
    if not ac:
        return utf8_response({"status": "no","msg": "激活码不存在"}, status_code=404)
    if ac.is_activated:
        return utf8_response({"status": "no","msg": "激活码已被激活过！"}, status_code=400)
    
    ac.is_activated = True
    beijing_tz = datetime.timezone(datetime.timedelta(hours=8))
    ac.activate_time = datetime.datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")

    db.commit()
    db.refresh(ac)
    return utf8_response({"status": "ok", "msg": "激活成功"})

# 重置激活状态接口（添加Request参数）
@app.post("/reset_activation")  
def reset_activation(
    request: Request,
    code: str = Form(...), 
    db: Session = Depends(get_db)
):
    activation_code = db.query(ActivationCode).filter(ActivationCode.code == code).first()
    if not activation_code:
        return utf8_response({"msg": "激活码不存在"}, status_code=400)
    
    if not activation_code.is_activated:
        return utf8_response({"msg": "该激活码已是未激活状态，无需重置"}, status_code=400)
    
    activation_code.is_activated = False
    activation_code.activate_time = None
    db.commit()
    db.refresh(activation_code)

    return utf8_response({
        "status": "ok",
        "msg": f"激活码【{code}】已重置为未激活状态", 
        "code": code
    })

# 重置查询次数接口（最终版：统一utf8_response，添加Request，修复文档问题）
@app.post("/reset_query_count", summary="重置激活码查询次数为0")
def reset_query_count(
    request: Request,
    actcode: str = Form(..., description="需要重置的激活码（32位）"),
    db: Session = Depends(get_db)
):
    actcode = actcode.strip()
    if not actcode:
        return utf8_response({
            "msg": "激活码不能为空",
            "is_success": False,
            "query_count": 0
        }, status_code=400)
    
    if len(actcode) != 32:
        return utf8_response({
            "msg": "激活码长度必须为32位",
            "is_success": False,
            "query_count": 0
        }, status_code=400)

    try:
        ac = db.query(ActivationCode).filter(ActivationCode.code == actcode).first()
        
        if not ac:
            return utf8_response({
                "msg": "激活码不存在",
                "is_success": False,
                "query_count": 0
            }, status_code=404)
        
        ac.query_count = 0
        db.commit()
        db.refresh(ac)
        
        return utf8_response({
            "msg": "激活码查询次数重置成功",
            "is_success": True,
            "query_count": ac.query_count
        }, status_code=200)
    
    except SQLAlchemyError as e:
        db.rollback()
        return utf8_response({
            "msg": f"数据库操作失败：{str(e)}",
            "is_success": False,
            "query_count": 0
        }, status_code=500)

# 删除激活码接口（添加Request参数）
@app.post("/delete_code")
def delete_code(
    request: Request,
    code: str = Form(...), 
    db: Session = Depends(get_db)
):
    activation_code = db.query(ActivationCode).filter(ActivationCode.code == code).first()
    if not activation_code:
        return utf8_response({"msg": "激活码不存在"}, status_code=400)
    
    if activation_code.is_activated:
        return utf8_response({"msg": "禁止删除已激活的激活码"}, status_code=403)
    
    db.delete(activation_code)
    db.commit()
    
    return utf8_response({"status": "ok","msg": f"激活码【{code}】已成功删除"})

# 获取激活码列表
@app.get("/get_codes")
def get_codes(page: int = 1, size: int = 10, db: Session = Depends(get_db)):
    try:
        page = max(1, page)
        size = max(1, min(100, size))
        total = db.execute(text("SELECT COUNT(*) FROM activation_codes")).scalar() or 0
        codes = db.execute(
            text("""
                SELECT id, code, raw_data, is_activated, activate_time, create_time
                FROM activation_codes
                LIMIT :size OFFSET :offset
            """),
            {"size": size, "offset": (page-1)*size}
        ).fetchall()
        
        data = []
        for c in codes:
            data.append({
                "id": c[0] if c[0] else "",
                "code": c[1] if c[1] else "",
                "raw_data": c[2] if c[2] else "",
                "is_activated": bool(c[3]) if c[3] is not None else False,
                "activate_time": format_datetime(c[4]),
                "create_time": format_datetime(c[5])
            })
        return utf8_response({"status": "ok","total": total, "list": data})
    except Exception as e:
        print(f"get_codes错误：{str(e)}")
        return utf8_response({"msg": f"查询失败：{str(e)}"}, status_code=500)

# 退出登录
@app.get("/logout")
def logout():
    return utf8_response({"status": "ok","msg": "退出成功"})

# 健康检查
@app.get("/health")
def health():
    return utf8_response({"status": "ok", "msg": "服务正常运行"})

# 获取产品信息
@app.get("/get_product_info")
def get_product_info(id: int, db: Session = Depends(get_db)):
    info = db.query(ProductInfo).filter(ProductInfo.id == id).first()
    if not info:
        return utf8_response({"msg": "产品信息不存在"}, status_code=404)
    return utf8_response({
        "status": "ok",
        "data": {
            "id": info.id,
            "guide_link": info.guide_link or "",
            "feishu_link": info.feishu_link or "",
            "shortcut_link": info.shortcut_link or ""
        }
    })
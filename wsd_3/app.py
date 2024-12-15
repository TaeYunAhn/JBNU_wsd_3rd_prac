from datetime import datetime, timedelta, date
from typing import Optional, List
from functools import wraps
import base64
import logging
import os
from flask import Flask, request, jsonify, g
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
from jose import JWTError, jwt
import werkzeug
from werkzeug.utils import secure_filename
import enum
import secrets


app = Flask(__name__)
CORS(app)

dbconfig = {
    "host": '113.198.66.75',
    "user": 'admin',
    "password": 'xodbs1234',
    "database": 'wsd3',
    "port": 13145
}

SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

db_pool = pooling.MySQLConnectionPool(pool_name="mypool", pool_size=5, **dbconfig)


def get_db():
    if 'db' not in g:
        g.db = db_pool.get_connection()
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def base64_encode_password(raw_password: str) -> str:
    return base64.b64encode(raw_password.encode('utf-8')).decode('utf-8')


def verify_password(plain: str, encoded: str) -> bool:
    return base64_encode_password(plain) == encoded


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    if "sub" in data and not isinstance(data["sub"], str):
        data["sub"] = str(data["sub"])

    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict):
    if "sub" in data and not isinstance(data["sub"], str):
        data["sub"] = str(data["sub"])

    expire = datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "scope": "refresh_token"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None

    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT user_id, email, name, status, phone, birth_date 
            FROM users 
            WHERE user_id=%s
            """,
            (user_id,)
        )
        user = cursor.fetchone()
        cursor.close()

        if not user or user['status'] in ['inactive', 'blocked']:
            return None

        return user

    except (JWTError, ValueError):
        return None


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return jsonify({"message": "Authentication required"}), 401
        g.current_user = user
        return f(*args, **kwargs)

    return decorated_function


SWAGGER_URL = '/api/docs'
API_URL = '/static/swagger.json'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Job API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)


@app.route('/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided"}), 400

    required_fields = ['email', 'password', 'name']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT user_id FROM users WHERE email=%s", (data['email'],))
        if cursor.fetchone():
            return jsonify({"message": "Email already registered"}), 400

        hashed_pw = base64_encode_password(data['password'])

        cursor.execute(
            """
            INSERT INTO users(email, password_hash, name, phone, birth_date, status) 
            VALUES (%s, %s, %s, %s, %s, 'active')
            """,
            (data['email'], hashed_pw, data['name'],
             data.get('phone'), data.get('birth_date'))
        )
        db.commit()
        user_id = cursor.lastrowid

        access_token = create_access_token(data={"sub": str(user_id)})
        refresh_token = create_refresh_token(data={"sub": str(user_id)})

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        })

    except Exception as e:
        db.rollback()
        return jsonify({"message": str(e)}), 500
    finally:
        cursor.close()


@app.route('/auth/login', methods=['POST'])
def login():
    if request.content_type == 'application/x-www-form-urlencoded':
        username = request.form.get('username')
        password = request.form.get('password')
    else:
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid request format"}), 400
        username = data.get('username')
        password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT user_id, password_hash, status FROM users WHERE email=%s",
            (username,)
        )
        user = cursor.fetchone()

        if not user or user['status'] != 'active':
            return jsonify({"message": "Invalid credentials"}), 401

        if not verify_password(password, user['password_hash']):
            return jsonify({"message": "Invalid credentials"}), 401

        access_token = create_access_token(data={"sub": str(user['user_id'])})
        refresh_token = create_refresh_token(data={"sub": str(user['user_id'])})

        cursor.execute(
            "UPDATE users SET last_login=NOW() WHERE user_id=%s",
            (user['user_id'],)
        )
        db.commit()

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        })
    finally:
        cursor.close()


@app.route('/auth/refresh', methods=['POST'])
def refresh_token():
    data = request.get_json()
    if not data or 'refresh_token' not in data:
        return jsonify({"message": "Refresh token is required"}), 400

    try:
        payload = jwt.decode(data['refresh_token'], SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("scope") != "refresh_token":
            return jsonify({"message": "Invalid token type"}), 401

        user_id = int(payload.get("sub"))

        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT user_id, status FROM users WHERE user_id=%s",
                (user_id,)
            )
            user = cursor.fetchone()

            if not user or user['status'] != 'active':
                return jsonify({"message": "User is not active"}), 401

            access_token = create_access_token(data={"sub": str(user_id)})
            new_refresh_token = create_refresh_token(data={"sub": str(user_id)})

            return jsonify({
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "token_type": "bearer"
            })

        finally:
            cursor.close()

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Refresh token has expired"}), 401
    except (jwt.JWTError, ValueError):
        return jsonify({"message": "Invalid refresh token"}), 401


@app.route('/auth/profile', methods=['PUT'])
@login_required
def update_profile():
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided"}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        updates = {}
        allowed_fields = ['name', 'phone', 'birth_date']

        for field in allowed_fields:
            if field in data:
                updates[field] = data[field]

        if 'current_password' in data and 'new_password' in data:
            cursor.execute(
                "SELECT password_hash FROM users WHERE user_id = %s",
                (g.current_user['user_id'],)
            )
            current_hash = cursor.fetchone()[0]

            if not verify_password(data['current_password'], current_hash):
                return jsonify({"message": "Current password is incorrect"}), 400

            updates['password_hash'] = base64_encode_password(data['new_password'])

        if not updates:
            return jsonify({"message": "No valid fields to update"}), 400

        set_clause = ", ".join(f"{key} = %s" for key in updates)
        query = f"UPDATE users SET {set_clause} WHERE user_id = %s"
        cursor.execute(query, list(updates.values()) + [g.current_user['user_id']])
        db.commit()

        return jsonify({"message": "Profile updated successfully"})

    except Exception as e:
        db.rollback()
        return jsonify({"message": str(e)}), 500
    finally:
        cursor.close()


@app.route('/jobs', methods=['GET'])
def list_jobs():
    keyword = request.args.get('keyword')
    company = request.args.get('company')
    employment_type = request.args.get('employment_type')
    position = request.args.get('position')

    location_id = request.args.get('location_id')
    salary_info = request.args.get('salary_info')
    experience_level = request.args.get('experience_level')
    sort_field = request.args.get('sort_field', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')

    job_categories = request.args.getlist('job_categories')
    tech_stacks = request.args.getlist('tech_stacks')
    page = int(request.args.get('page', 1))

    query = """
    SELECT DISTINCT
        jp.posting_id,
        c.name as company_name,
        jp.title,
        jp.job_description,
        jp.experience_level,
        jp.education_level,
        jp.employment_type,
        jp.salary_info,
        jp.location_id,
        CONCAT(l.city, ' ', COALESCE(l.district, '')) as location,
        jp.deadline_date,
        jp.view_count,
        jp.created_at,
        GROUP_CONCAT(DISTINCT ts.name) as tech_stacks,
        GROUP_CONCAT(DISTINCT jc.name) as job_categories
    FROM job_postings jp
    JOIN companies c ON jp.company_id = c.company_id
    LEFT JOIN locations l ON jp.location_id = l.location_id
    LEFT JOIN posting_tech_stacks pts ON jp.posting_id = pts.posting_id
    LEFT JOIN tech_stacks ts ON pts.stack_id = ts.stack_id
    LEFT JOIN posting_categories pc ON jp.posting_id = pc.posting_id
    LEFT JOIN job_categories jc ON pc.category_id = jc.category_id
    WHERE jp.status = 'active'
    """

    params = []

    if keyword:
        query += " AND (jp.title LIKE %s OR jp.job_description LIKE %s)"
        params.extend([f"%{keyword}%", f"%{keyword}%"])
    if company:
        query += " AND c.name LIKE %s"
        params.append(f"%{company}%")
    if employment_type:
        query += " AND jp.employment_type = %s"
        params.append(employment_type)
    if position:
        query += " AND jp.title LIKE %s"
        params.append(f"%{position}%")

    if location_id:
        query += " AND jp.location_id = %s"
        params.append(location_id)
    if salary_info:
        query += " AND jp.salary_info LIKE %s"
        params.append(f"%{salary_info}%")
    if experience_level:
        query += " AND jp.experience_level = %s"
        params.append(experience_level)
    if tech_stacks:
        query += f" AND ts.name IN ({','.join(['%s'] * len(tech_stacks))})"
        params.extend(tech_stacks)
    if job_categories:
        query += f" AND jc.name IN ({','.join(['%s'] * len(job_categories))})"
        params.extend(job_categories)

    query += " GROUP BY jp.posting_id"

    valid_sort_fields = {
        'created_at': 'jp.created_at',
        'view_count': 'jp.view_count',
        'deadline_date': 'jp.deadline_date',
        'title': 'jp.title'
    }

    sort_field = valid_sort_fields.get(sort_field, 'jp.created_at')
    sort_direction = 'DESC' if sort_order.lower() == 'desc' else 'ASC'
    query += f" ORDER BY {sort_field} {sort_direction}"

    page_size = 20
    offset = (page - 1) * page_size
    query += f" LIMIT {page_size} OFFSET {offset}"

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(query, params)
        jobs = cursor.fetchall()

        for job in jobs:
            if job['tech_stacks']:
                job['tech_stacks'] = job['tech_stacks'].split(',')
            else:
                job['tech_stacks'] = []

            if job['job_categories']:
                job['job_categories'] = job['job_categories'].split(',')
            else:
                job['job_categories'] = []

        return jsonify({
            "jobs": jobs,
            "page": page,
            "page_size": page_size,
            "sort_field": sort_field,
            "sort_order": sort_order
        })
    finally:
        cursor.close()


@app.route('/jobs/<int:id>', methods=['GET'])
def get_job_detail(id):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("UPDATE job_postings SET view_count = view_count + 1 WHERE posting_id = %s", (id,))
        db.commit()

        query = """
        SELECT 
            jp.*,
            c.name as company_name,
            l.city,
            l.district,
            GROUP_CONCAT(DISTINCT ts.name) as tech_stacks,
            GROUP_CONCAT(DISTINCT jc.name) as job_categories
        FROM job_postings jp
        JOIN companies c ON jp.company_id = c.company_id
        LEFT JOIN locations l ON jp.location_id = l.location_id
        LEFT JOIN posting_tech_stacks pts ON jp.posting_id = pts.posting_id
        LEFT JOIN tech_stacks ts ON pts.stack_id = ts.stack_id
        LEFT JOIN posting_categories pc ON jp.posting_id = pc.posting_id
        LEFT JOIN job_categories jc ON pc.category_id = jc.category_id
        WHERE jp.posting_id = %s AND jp.status != 'deleted'
        GROUP BY jp.posting_id
        """

        cursor.execute(query, (id,))
        job = cursor.fetchone()

        if not job:
            return jsonify({"message": "Job not found"}), 404

        if job['tech_stacks']:
            job['tech_stacks'] = job['tech_stacks'].split(',')
        else:
            job['tech_stacks'] = []

        if job['job_categories']:
            job['job_categories'] = job['job_categories'].split(',')
        else:
            job['job_categories'] = []

        related_query = """
        SELECT DISTINCT jp.posting_id, jp.title, c.name as company_name
        FROM job_postings jp
        JOIN companies c ON jp.company_id = c.company_id
        LEFT JOIN posting_tech_stacks pts ON jp.posting_id = pts.posting_id
        LEFT JOIN tech_stacks ts ON pts.stack_id = ts.stack_id
        WHERE jp.status = 'active' 
        AND jp.posting_id != %s
        AND (jp.company_id = %s 
             OR ts.name IN (SELECT ts2.name 
                           FROM posting_tech_stacks pts2 
                           JOIN tech_stacks ts2 ON pts2.stack_id = ts2.stack_id 
                           WHERE pts2.posting_id = %s))
        ORDER BY RAND()
        LIMIT 5
        """

        cursor.execute(related_query, (id, job['company_id'], id))
        related = cursor.fetchall()

        return jsonify({"job": job, "related": related})
    finally:
        cursor.close()


@app.route('/jobs', methods=['POST'])
@login_required
def create_job():
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided"}), 400

    required_fields = ['company_id', 'title', 'job_description']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        location_id = None
        if 'location' in data:
            cursor.execute(
                """
                SELECT location_id FROM locations 
                WHERE city = %s AND (district = %s OR (district IS NULL AND %s IS NULL))
                """,
                (data['location']['city'], data['location'].get('district'),
                 data['location'].get('district'))
            )
            location_result = cursor.fetchone()

            if location_result:
                location_id = location_result['location_id']
            else:
                cursor.execute(
                    "INSERT INTO locations (city, district) VALUES (%s, %s)",
                    (data['location']['city'], data['location'].get('district'))
                )
                location_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO job_postings(
                company_id, title, job_description, experience_level,
                education_level, employment_type, salary_info,
                location_id, deadline_date, status, view_count
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', 0)
            """,
            (data['company_id'], data['title'], data['job_description'],
             data.get('experience_level'), data.get('education_level'),
             data.get('employment_type'), data.get('salary_info'),
             location_id, data.get('deadline_date'))
        )

        posting_id = cursor.lastrowid

        if data.get('tech_stacks'):
            for tech in data['tech_stacks']:
                cursor.execute("SELECT stack_id FROM tech_stacks WHERE name = %s", (tech,))
                result = cursor.fetchone()
                if result:
                    stack_id = result['stack_id']
                else:
                    cursor.execute(
                        "INSERT INTO tech_stacks (name, category) VALUES (%s, 'Other')",
                        (tech,)
                    )
                    stack_id = cursor.lastrowid

                cursor.execute(
                    "INSERT INTO posting_tech_stacks (posting_id, stack_id) VALUES (%s, %s)",
                    (posting_id, stack_id)
                )

        if data.get('job_categories'):
            for category in data['job_categories']:
                cursor.execute(
                    "SELECT category_id FROM job_categories WHERE name = %s",
                    (category,)
                )
                result = cursor.fetchone()
                if result:
                    category_id = result['category_id']
                else:
                    cursor.execute(
                        "INSERT INTO job_categories (name) VALUES (%s)",
                        (category,)
                    )
                    category_id = cursor.lastrowid

                cursor.execute(
                    "INSERT INTO posting_categories (posting_id, category_id) VALUES (%s, %s)",
                    (posting_id, category_id)
                )

        db.commit()
        return jsonify({
            "message": "Job posting created successfully",
            "posting_id": posting_id
        })

    except Exception as e:
        db.rollback()
        return jsonify({"message": str(e)}), 500
    finally:
        cursor.close()


@app.route('/jobs/<int:id>', methods=['PUT'])
@login_required
def update_job(id):
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided"}), 400

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT jp.*, l.city, l.district 
            FROM job_postings jp
            LEFT JOIN locations l ON jp.location_id = l.location_id
            WHERE jp.posting_id = %s
            """,
            (id,)
        )
        existing_job = cursor.fetchone()
        if not existing_job:
            return jsonify({"message": "Job posting not found"}), 404

        updates = {}
        update_fields = [
            'title', 'job_description', 'experience_level', 'education_level',
            'employment_type', 'salary_info', 'deadline_date', 'status'
        ]

        for field in update_fields:
            if field in data:
                updates[field] = data[field]

        if 'location' in data:
            cursor.execute(
                """
                SELECT location_id FROM locations 
                WHERE city = %s AND (district = %s OR (district IS NULL AND %s IS NULL))
                """,
                (data['location']['city'], data['location'].get('district'),
                 data['location'].get('district'))
            )
            location_result = cursor.fetchone()

            if location_result:
                updates['location_id'] = location_result['location_id']
            else:
                cursor.execute(
                    "INSERT INTO locations (city, district) VALUES (%s, %s)",
                    (data['location']['city'], data['location'].get('district'))
                )
                updates['location_id'] = cursor.lastrowid

        if updates:
            set_clause = ", ".join(f"{key} = %s" for key in updates)
            query = f"UPDATE job_postings SET {set_clause} WHERE posting_id = %s"
            cursor.execute(query, list(updates.values()) + [id])

        if 'tech_stacks' in data:
            cursor.execute("DELETE FROM posting_tech_stacks WHERE posting_id = %s", (id,))
            for tech in data['tech_stacks']:
                cursor.execute("SELECT stack_id FROM tech_stacks WHERE name = %s", (tech,))
                result = cursor.fetchone()
                if result:
                    stack_id = result['stack_id']
                else:
                    cursor.execute(
                        "INSERT INTO tech_stacks (name) VALUES (%s)",
                        (tech,)
                    )
                    stack_id = cursor.lastrowid

                cursor.execute(
                    """
                    INSERT INTO posting_tech_stacks (posting_id, stack_id)
                    VALUES (%s, %s)
                    """,
                    (id, stack_id)
                )

        if 'job_categories' in data:
            cursor.execute("DELETE FROM posting_categories WHERE posting_id = %s", (id,))
            for category in data['job_categories']:
                cursor.execute(
                    "SELECT category_id FROM job_categories WHERE name = %s",
                    (category,)
                )
                result = cursor.fetchone()
                if result:
                    category_id = result['category_id']
                else:
                    cursor.execute(
                        "INSERT INTO job_categories (name) VALUES (%s)",
                        (category,)
                    )
                    category_id = cursor.lastrowid

                cursor.execute(
                    """
                    INSERT INTO posting_categories (posting_id, category_id)
                    VALUES (%s, %s)
                    """,
                    (id, category_id)
                )

        db.commit()
        return jsonify({"message": "Job posting updated successfully"})

    except Exception as e:
        db.rollback()
        return jsonify({"message": str(e)}), 500
    finally:
        cursor.close()


@app.route('/jobs/<int:id>', methods=['DELETE'])
@login_required
def delete_job(id):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT status FROM job_postings WHERE posting_id = %s",
            (id,)
        )
        job = cursor.fetchone()

        if not job:
            return jsonify({"message": "Job posting not found"}), 404

        if job['status'] == 'deleted':
            return jsonify({"message": "Job posting already deleted"}), 400

        cursor.execute(
            "UPDATE job_postings SET status='deleted' WHERE posting_id=%s",
            (id,)
        )
        db.commit()

        return jsonify({"message": "Job posting deleted successfully"})

    except Exception as e:
        db.rollback()
        return jsonify({"message": str(e)}), 500
    finally:
        cursor.close()


@app.route('/applications', methods=['POST'])
@login_required
def apply_for_job():
    try:
        if request.content_type.startswith('multipart/form-data'):
            posting_id = request.form.get('posting_id')
            resume_id = request.form.get('resume_id')
            resume_file = request.files.get('resume_file')
        else:
            data = request.get_json()
            posting_id = data.get('posting_id')
            resume_id = data.get('resume_id')
            resume_file = None

        if not posting_id:
            return jsonify({"message": "Posting ID is required"}), 400

        if not resume_id and not resume_file:
            return jsonify({"message": "Either resume_id or resume_file must be provided"}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT application_id FROM applications 
            WHERE user_id=%s AND posting_id=%s
            """,
            (g.current_user['user_id'], posting_id)
        )

        if cursor.fetchone():
            return jsonify({"message": "Already applied for this job posting"}), 400

        if resume_file:
            if not resume_file.filename.lower().endswith('.pdf'):
                return jsonify({"message": "Only PDF files are allowed"}), 400

            file_content = resume_file.read()
            cursor.execute(
                """
                INSERT INTO resumes(user_id, title, content, is_primary)
                VALUES(%s, %s, %s, 0)
                """,
                (g.current_user['user_id'], f"Resume {datetime.now()}", file_content)
            )
            db.commit()
            resume_id = cursor.lastrowid

        if resume_id:
            cursor.execute(
                "SELECT resume_id, user_id FROM resumes WHERE resume_id=%s",
                (resume_id,)
            )
            resume = cursor.fetchone()
            if not resume or resume['user_id'] != g.current_user['user_id']:
                return jsonify({
                    "message": "Not authorized to use this resume or resume does not exist"
                }), 403

        cursor.execute(
            """
            INSERT INTO applications(user_id, posting_id, resume_id, status)
            VALUES (%s, %s, %s, 'pending')
            """,
            (g.current_user['user_id'], posting_id, resume_id)
        )
        db.commit()
        application_id = cursor.lastrowid

        return jsonify({
            "message": "Application submitted successfully",
            "application_id": application_id
        })

    except Exception as e:
        db.rollback()
        return jsonify({"message": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()


@app.route('/applications', methods=['GET'])
@login_required
def list_applications():
    status_filter = request.args.get('status_filter')
    sort_by_date = request.args.get('sort_by_date', 'desc')
    page = int(request.args.get('page', 1))

    query = """
    SELECT a.application_id, a.posting_id, jp.title, a.status, a.applied_at
    FROM applications a
    JOIN job_postings jp ON a.posting_id=jp.posting_id
    WHERE a.user_id=%s
    """
    params = [g.current_user['user_id']]

    if status_filter:
        query += " AND a.status=%s"
        params.append(status_filter)

    if sort_by_date == "asc":
        query += " ORDER BY a.applied_at ASC"
    else:
        query += " ORDER BY a.applied_at DESC"

    page_size = 20
    offset = (page - 1) * page_size
    query += f" LIMIT {page_size} OFFSET {offset}"

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(query, params)
        applications = cursor.fetchall()
        return jsonify(applications)
    finally:
        cursor.close()


@app.route('/applications/<int:id>', methods=['DELETE'])
@login_required
def cancel_application(id):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT user_id FROM applications WHERE application_id=%s",
            (id,)
        )
        application = cursor.fetchone()

        if not application:
            return jsonify({"message": "Application not found"}), 404

        if application['user_id'] != g.current_user['user_id']:
            return jsonify({"message": "Not authorized to cancel this application"}), 403

        cursor.execute(
            "DELETE FROM applications WHERE application_id=%s",
            (id,)
        )
        db.commit()

        return jsonify({"message": "Application cancelled successfully"})

    finally:
        cursor.close()


@app.route('/bookmarks', methods=['POST'])
@login_required
def toggle_bookmark():
    data = request.get_json()
    if not data or 'posting_id' not in data:
        return jsonify({"message": "Posting ID is required"}), 400

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT bookmark_id FROM bookmarks 
            WHERE user_id=%s AND posting_id=%s
            """,
            (g.current_user['user_id'], data['posting_id'])
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                "DELETE FROM bookmarks WHERE bookmark_id=%s",
                (existing['bookmark_id'],)
            )
            db.commit()
            return jsonify({"message": "Bookmark removed"})
        else:
            cursor.execute(
                "INSERT INTO bookmarks(user_id, posting_id) VALUES(%s,%s)",
                (g.current_user['user_id'], data['posting_id'])
            )
            db.commit()
            return jsonify({"message": "Bookmark added"})

    finally:
        cursor.close()


@app.route('/bookmarks', methods=['GET'])
@login_required
def list_bookmarks():
    page = int(request.args.get('page', 1))
    sort = request.args.get('sort', 'desc')

    query = """
    SELECT 
        b.bookmark_id, 
        b.posting_id, 
        jp.title,
        jp.job_description,
        jp.experience_level,
        jp.education_level,
        jp.employment_type,
        jp.salary_info,
        CONCAT(l.city, ' ', COALESCE(l.district, '')) as location,
        jp.deadline_date,
        jp.view_count,
        c.name as company_name,
        GROUP_CONCAT(DISTINCT ts.name) as tech_stacks,
        GROUP_CONCAT(DISTINCT jc.name) as job_categories
    FROM bookmarks b
    JOIN job_postings jp ON b.posting_id = jp.posting_id
    JOIN companies c ON jp.company_id = c.company_id
    LEFT JOIN locations l ON jp.location_id = l.location_id
    LEFT JOIN posting_tech_stacks pts ON jp.posting_id = pts.posting_id
    LEFT JOIN tech_stacks ts ON pts.stack_id = ts.stack_id
    LEFT JOIN posting_categories pc ON jp.posting_id = pc.posting_id
    LEFT JOIN job_categories jc ON pc.category_id = jc.category_id
    WHERE b.user_id = %s
    GROUP BY b.bookmark_id
    """

    if sort == "asc":
        query += " ORDER BY b.created_at ASC"
    else:
        query += " ORDER BY b.created_at DESC"

    page_size = 20
    offset = (page - 1) * page_size
    query += f" LIMIT {page_size} OFFSET {offset}"

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(query, (g.current_user['user_id'],))
        bookmarks = cursor.fetchall()

        for bookmark in bookmarks:
            if bookmark['tech_stacks']:
                bookmark['tech_stacks'] = bookmark['tech_stacks'].split(',')
            else:
                bookmark['tech_stacks'] = []

            if bookmark['job_categories']:
                bookmark['job_categories'] = bookmark['job_categories'].split(',')
            else:
                bookmark['job_categories'] = []

        return jsonify(bookmarks)
    finally:
        cursor.close()


@app.errorhandler(400)
def bad_request(error):
    return jsonify({"message": "Bad request"}), 400


@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"message": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error):
    return jsonify({"message": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(error):
    return jsonify({"message": "Not found"}), 404


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"message": "Internal server error"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=19051, debug=True)


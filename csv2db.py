import pandas as pd
import mysql.connector
from mysql.connector import Error
import logging
from typing import Dict, Optional, List
from functools import wraps
import time
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('db_loader.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

def retry_on_error(max_retries: int = 3, delay: int = 1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Error as e:
                    retries += 1
                    if retries == max_retries:
                        logging.error(f"Failed after {max_retries} attempts: {str(e)}")
                        raise
                    logging.warning(f"Attempt {retries} failed, retrying in {delay} seconds...")
                    time.sleep(delay)
            return None
        return wrapper
    return decorator

class JobDatabase:
    def __init__(self):
        try:
            self.conn = mysql.connector.connect(
                host="localhost",
                port=3000,
                user="root",
                password="xodbs1234",
                database="wsd3"
            )
            self.cursor = self.conn.cursor(dictionary=True)
            self._init_tech_stacks()
            self._init_job_categories()
            self.tech_stack_cache = self._load_tech_stacks()
            self.category_cache = self._load_job_categories()
        except Error as e:
            logging.error(f"Error connecting to database: {e}")
            raise

    def _load_tech_stacks(self) -> Dict[str, int]:
        """Load tech stacks from database into cache"""
        try:
            self.cursor.execute("SELECT stack_id, name FROM tech_stacks")
            return {row['name'].lower(): row['stack_id'] for row in self.cursor.fetchall()}
        except Error as e:
            logging.error(f"Error loading tech stacks: {e}")
            return {}

    def _load_job_categories(self) -> Dict[str, int]:
        """Load job categories from database into cache"""
        try:
            self.cursor.execute("SELECT category_id, name FROM job_categories")
            return {row['name']: row['category_id'] for row in self.cursor.fetchall()}
        except Error as e:
            logging.error(f"Error loading job categories: {e}")
            return {}

    def _init_tech_stacks(self):
        """Initialize tech stacks table with common technologies"""
        tech_stacks = [
            ('Python', 'Programming'),
            ('Java', 'Programming'),
            ('C++', 'Programming'),
            ('Linux', 'System'),
            ('AWS', 'Cloud'),
            ('React', 'Frontend'),
            ('Django', 'Backend'),
            ('Spring', 'Backend'),
            ('웹개발', 'Web'),
            ('앱개발', 'Mobile'),
            ('백엔드', 'Backend'),
            ('프론트엔드', 'Frontend'),
            ('머신러닝', 'AI'),
            ('딥러닝', 'AI'),
            ('AI', 'AI'),
            ('DevOps', 'DevOps'),
            ('Git', 'Tool'),
            ('API', 'Development')
        ]

        try:
            for name, category in tech_stacks:
                self.cursor.execute(
                    "INSERT IGNORE INTO tech_stacks (name, category) VALUES (%s, %s)",
                    (name, category)
                )
            self.conn.commit()
        except Error as e:
            logging.error(f"Error initializing tech stacks: {e}")
            self.conn.rollback()

    def _init_job_categories(self):
        """Initialize job categories table with common categories"""
        categories = [
            '신입',
            '경력',
            '신입·경력',
            '경력무관',
            '인턴',
            '전문연구요원'
        ]

        try:
            for category in categories:
                self.cursor.execute(
                    "INSERT IGNORE INTO job_categories (name) VALUES (%s)",
                    (category,)
                )
            self.conn.commit()
        except Error as e:
            logging.error(f"Error initializing job categories: {e}")
            self.conn.rollback()

    @retry_on_error()
    def insert_company(self, company_name: str) -> Optional[int]:
        """Insert a company if it doesn't exist and return its ID"""
        try:
            self.cursor.execute("SELECT company_id FROM companies WHERE name = %s", (company_name,))
            result = self.cursor.fetchone()
            
            if result:
                return result['company_id']
            
            self.cursor.execute("INSERT INTO companies (name) VALUES (%s)", (company_name,))
            self.conn.commit()
            return self.cursor.lastrowid
        except Error as e:
            logging.error(f"Error inserting company: {e}")
            self.conn.rollback()
            raise

    @retry_on_error()
    def insert_location(self, location: str) -> Optional[int]:
        """Insert a location if it doesn't exist and return its ID"""
        try:
            if pd.isna(location):
                return None
                
            parts = location.split(' ', 1)
            city = parts[0]
            district = parts[1] if len(parts) > 1 else None
            
            self.cursor.execute(
                """
                SELECT location_id FROM locations 
                WHERE city = %s AND (district = %s OR (district IS NULL AND %s IS NULL))
                """, 
                (city, district, district)
            )
            result = self.cursor.fetchone()
            
            if result:
                return result['location_id']
            
            self.cursor.execute(
                "INSERT INTO locations (city, district) VALUES (%s, %s)",
                (city, district)
            )
            self.conn.commit()
            return self.cursor.lastrowid
        except Error as e:
            logging.error(f"Error inserting location: {e}")
            self.conn.rollback()
            raise

    @retry_on_error()
    def get_tech_stacks(self, tech_text: str) -> List[int]:
        """Extract and return tech stack IDs from text"""
        if pd.isna(tech_text):
            return []
            
        tech_text = tech_text.split('외')[0]
        techs = [t.strip() for t in tech_text.split(',')]
        tech_ids = []
        
        for tech in techs:
            tech_lower = tech.lower()
            if tech_lower in self.tech_stack_cache:
                tech_ids.append(self.tech_stack_cache[tech_lower])
            
        return tech_ids

    @retry_on_error()
    def get_categories(self, experience: str) -> List[int]:
        """Get category IDs based on experience level"""
        if pd.isna(experience):
            return []
            
        experience = experience.strip()
        category_ids = []
        
        if experience in self.category_cache:
            category_ids.append(self.category_cache[experience])
            
        return category_ids

    @retry_on_error()
    def insert_job_posting(self, job_data: Dict) -> Optional[int]:
        """Insert a job posting and its related data"""
        try:
            self.cursor.execute(
                "SELECT posting_id FROM job_postings WHERE company_id = %s AND title = %s",
                (job_data['company_id'], job_data['title'])
            )
            if self.cursor.fetchone():
                logging.info(f"Job posting already exists: {job_data['title']}")
                return None

            query = """
                INSERT INTO job_postings (
                    company_id, title, job_description, experience_level,
                    education_level, employment_type, salary_info,
                    location_id, deadline_date, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'active')
            """
            values = (
                job_data['company_id'],
                job_data['title'],
                job_data['job_description'],
                job_data['experience_level'],
                job_data['education_level'],
                job_data['employment_type'],
                job_data['salary_info'],
                job_data['location_id'],
                job_data['deadline_date']
            )
            
            self.cursor.execute(query, values)
            posting_id = self.cursor.lastrowid

            # Insert tech stacks
            for stack_id in job_data['tech_stacks']:
                self.cursor.execute(
                    "INSERT INTO posting_tech_stacks (posting_id, stack_id) VALUES (%s, %s)",
                    (posting_id, stack_id)
                )

            # Insert categories
            for category_id in job_data['categories']:
                self.cursor.execute(
                    "INSERT INTO posting_categories (posting_id, category_id) VALUES (%s, %s)",
                    (posting_id, category_id)
                )

            self.conn.commit()
            return posting_id
        except Error as e:
            logging.error(f"Error inserting job posting: {e}")
            self.conn.rollback()
            raise

    def close(self):
        """Close database connections"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

def process_csv_file(filename: str):
    """Process CSV file and insert data into database"""
    db = JobDatabase()
    try:
        df = pd.read_csv(filename)
        successful_inserts = 0
        skipped_records = 0
        
        for _, row in df.iterrows():
            try:
                company_id = db.insert_company(row['회사명'])
                location_id = db.insert_location(row['지역'])
                tech_stack_ids = db.get_tech_stacks(row['직무분야'])
                category_ids = db.get_categories(row['경력'])
                
                job_data = {
                    'company_id': company_id,
                    'title': row['제목'],
                    'job_description': row['링크'],
                    'experience_level': None if pd.isna(row['경력']) else row['경력'],
                    'education_level': None if pd.isna(row['학력']) else row['학력'],
                    'employment_type': None if pd.isna(row['고용형태']) else row['고용형태'],
                    'salary_info': None if pd.isna(row['연봉정보']) else row['연봉정보'],
                    'location_id': location_id,
                    'deadline_date': None if pd.isna(row['마감일']) else row['마감일'],
                    'tech_stacks': tech_stack_ids,
                    'categories': category_ids
                }
                
                posting_id = db.insert_job_posting(job_data)
                
                if posting_id:
                    successful_inserts += 1
                    logging.info(f"Successfully inserted job posting: {row['제목']}")
                else:
                    skipped_records += 1
                    logging.info(f"Skipped duplicate job posting: {row['제목']}")
                
            except Exception as e:
                logging.error(f"Error processing row: {row['제목']}, Error: {str(e)}")
                continue
        
        logging.info(f"Processing completed. Successfully inserted: {successful_inserts}, Skipped: {skipped_records}")
        
    except Exception as e:
        logging.error(f"Error processing CSV file: {str(e)}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    try:
        process_csv_file('saramin_python.csv')
    except Exception as e:
        logging.error(f"Program failed: {str(e)}")
        sys.exit(1)

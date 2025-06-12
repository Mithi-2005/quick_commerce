import boto3
from django.conf import settings
import uuid
from datetime import datetime

def generate_unique_filename(original_filename):
    """Generate a unique filename for S3 upload"""
    ext = original_filename.split('.')[-1]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_id = str(uuid.uuid4())[:8]
    return f"products/{timestamp}_{unique_id}.{ext}"

def upload_file_to_s3(file, folder='products'):
    """Upload a file to S3 and return the URL"""
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        # Generate unique filename
        filename = generate_unique_filename(file.name)
        
        # Upload file without ACL
        s3_client.upload_fileobj(
            file,
            settings.AWS_STORAGE_BUCKET_NAME,
            filename,
            ExtraArgs={
                'ContentType': file.content_type
            }
        )

        # Generate URL
        file_url = f"https://{settings.AWS_S3_CUSTOM_DOMAIN}/{filename}"
        return file_url

    except Exception as e:
        print(f"Error uploading file to S3: {str(e)}")
        raise e 
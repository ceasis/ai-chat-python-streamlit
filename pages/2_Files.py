import streamlit as st
import os
import boto3
from dotenv import load_dotenv
from botocore.exceptions import ClientError
import io

# Load environment variables
load_dotenv()

# Configure page
st.set_page_config(
    page_title="Files - HR Assistant",
    page_icon="📁",
    layout="wide"
)

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

BUCKET_NAME = os.getenv('BUCKET_NAME', 'chat-ai-assistant')  # Get from env or use default
PROJECT_NAME = os.getenv('PROJECT_NAME', 'hr-assistant')  # Get from env or use default
BUCKET_NAME = f'{BUCKET_NAME}-{PROJECT_NAME}'

def list_s3_files():
    """List all files in the S3 bucket"""
    try:
        response = s3_client.list_objects_v2(Bucket=BUCKET_NAME)
        files = []
        if 'Contents' in response:
            files = [obj['Key'] for obj in response['Contents']]
        return files
    except ClientError as e:
        st.error(f"Error listing files: {str(e)}")
        return []

def upload_to_s3(file_obj, filename):
    """Upload a file to S3"""
    try:
        s3_client.upload_fileobj(file_obj, BUCKET_NAME, filename)
        return True
    except ClientError as e:
        st.error(f"Error uploading file: {str(e)}")
        return False

def delete_from_s3(filename):
    """Delete a file from S3"""
    try:
        s3_client.delete_object(Bucket=BUCKET_NAME, Key=filename)
        return True
    except ClientError as e:
        st.error(f"Error deleting file: {str(e)}")
        return False

def read_file_from_s3(filename):
    """Read a file's content from S3"""
    try:
        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=filename)
        return response['Body'].read().decode('utf-8')
    except ClientError as e:
        st.error(f"Error reading file: {str(e)}")
        return None

def ensure_bucket_exists():
    """Check if bucket exists and create it if it doesn't"""
    try:
        s3_client.head_bucket(Bucket=BUCKET_NAME)
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == '404' or error_code == '403':
            try:
                # For regions other than us-east-1, we need to specify LocationConstraint
                region = os.getenv('AWS_DEFAULT_REGION')
                if region == 'us-east-1':
                    s3_client.create_bucket(Bucket=BUCKET_NAME)
                else:
                    s3_client.create_bucket(
                        Bucket=BUCKET_NAME,
                        CreateBucketConfiguration={'LocationConstraint': region}
                    )
                st.success(f"Created new S3 bucket: {BUCKET_NAME}")
                return True
            except ClientError as create_error:
                st.error(f"Error creating bucket: {str(create_error)}")
                return False
        else:
            st.error(f"Error checking bucket: {str(e)}")
            return False
    return True

# Ensure bucket exists before proceeding
if not ensure_bucket_exists():
    st.error("Unable to initialize storage. Please check your AWS credentials and permissions.")
    st.stop()

# Initialize session state for uploaded files if not exists
if "uploaded_files" not in st.session_state:
    st.session_state.uploaded_files = []


st.title("📁 Knowledge Base File Management")

# File upload section
st.header("Upload Files")
uploaded_file = st.file_uploader(
    "Choose a file to upload",
    type=["txt", "pdf", "doc", "docx"],
    help="Supported formats: TXT, PDF, DOC, DOCX"
)

if uploaded_file is not None:
    # Upload to S3
    if upload_to_s3(uploaded_file, uploaded_file.name):
        st.success(f"File uploaded successfully: {uploaded_file.name}")
        # Refresh the file list
        st.session_state.uploaded_files = list_s3_files()
    else:
        st.error("Failed to upload file")

# Display uploaded files
st.header("Uploaded Files")
# Refresh file list from S3
files = list_s3_files()
if not files:
    st.info("No files uploaded yet.")
else:
    for filename in files:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.write(filename)
        with col2:
            if st.button("View", key=f"view_{filename}"):
                content = read_file_from_s3(filename)
                if content:
                    st.text_area("File Content", content, height=200)
        with col3:
            if st.button("Delete", key=f"delete_{filename}"):
                if delete_from_s3(filename):
                    st.success(f"Deleted {filename}")
                    # Refresh the file list
                    st.rerun() 
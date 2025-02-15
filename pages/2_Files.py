import streamlit as st
import os

# Configure page
st.set_page_config(
    page_title="Files - AI Chat Assistant",
    page_icon="📁",
    layout="wide"
)

# Initialize session state for uploaded files if not exists
if "uploaded_files" not in st.session_state:
    st.session_state.uploaded_files = []

def save_uploaded_file(uploaded_file):
    """Save uploaded file to a 'uploads' directory"""
    # Create uploads directory if it doesn't exist
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    
    # Save the file
    file_path = os.path.join("uploads", uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return file_path

st.title("📁 Knowledge Base File Management")

# File upload section
st.header("Upload Files")
uploaded_file = st.file_uploader(
    "Choose a file to upload",
    type=["txt", "pdf", "doc", "docx"],
    help="Supported formats: TXT, PDF, DOC, DOCX"
)

if uploaded_file is not None:
    # Save the file
    file_path = save_uploaded_file(uploaded_file)
    
    # Add to session state if not already there
    if file_path not in st.session_state.uploaded_files:
        st.session_state.uploaded_files.append(file_path)
    
    st.success(f"File uploaded successfully: {uploaded_file.name}")

# Display uploaded files
st.header("Uploaded Files")
if not st.session_state.uploaded_files:
    st.info("No files uploaded yet.")
else:
    for file_path in st.session_state.uploaded_files:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.write(os.path.basename(file_path))
        with col2:
            if st.button("View", key=f"view_{file_path}"):
                with open(file_path, "r") as f:
                    content = f.read()
                st.text_area("File Content", content, height=200)
        with col3:
            if st.button("Delete", key=f"delete_{file_path}"):
                try:
                    os.remove(file_path)
                    st.session_state.uploaded_files.remove(file_path)
                    st.rerun()
                except Exception as e:
                    st.error(f"Error deleting file: {str(e)}") 
import streamlit as st

st.set_page_config(
    page_title="About - AI Chat Assistant",
    page_icon="ℹ️",
    layout="wide"
)

st.title("ℹ️ About This AI Chat Assistant")

st.markdown("""
## Overview
This AI Chat Assistant is built using Streamlit and OpenAI's GPT models. It provides an intuitive interface for having conversations with an AI assistant.

## Features
- Real-time chat interface
- Stream responses as they're generated
- Persistent chat history during session
- Multi-page application structure
- File management system
  - Upload documents
  - View uploaded files
  - Delete files when needed

## Technology Stack
- **Frontend**: Streamlit
- **AI Model**: OpenAI GPT-3.5-turbo
- **Language**: Python
- **File Storage**: Local filesystem

## How to Use
1. Enter your message in the chat input box
2. Wait for the AI to generate and stream its response
3. Continue the conversation as needed
4. Navigate to different pages using the sidebar
5. Use the Files page to manage your documents

## Setup
1. Install the required dependencies using `pip install -r requirements.txt`
2. Create a `.env` file with your OpenAI API key:
   ```
   OPENAI_API_KEY=your_api_key_here
   ```
3. Run the application using `streamlit run Home.py`
""") 


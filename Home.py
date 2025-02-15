import streamlit as st
import openai
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Configure page
st.set_page_config(
    page_title="HR Assistant",
    page_icon="🤖",
    layout="wide"
)

# Add custom CSS for right-aligned user messages
st.markdown("""
<style>
[data-testid="stChatMessage"] [data-testid="stMarkdownContainer"] {
    width: 75%;
}
[data-testid="stChatMessage"].user [data-testid="stMarkdownContainer"] {
    margin-left: 0;
    text-align: right;
    margin-right: auto;
    background-color: #2b313e;
    border-radius: 15px;
    padding: 0.5rem;
}
[data-testid="stChatMessage"].assistant [data-testid="stMarkdownContainer"] {
    margin-right: auto;
    margin-left: 0;
    background-color: #0e1117;
    border-radius: 10px;
    padding: 0.5rem;
}
.stButton button {
    width: 100%;
}
            
[data-testid="tooltipHoverTarget"] {
    width: 100% !important;
}
</style>
""", unsafe_allow_html=True)

# Add clear chat button to sidebar
if st.sidebar.button("🗑️ Clear Chat History", help="Clear the chat history"):
    st.session_state.messages = []
    st.rerun()

# Initialize session state for message history
if "messages" not in st.session_state:
    st.session_state.messages = []

def initialize_openai():
    """Initialize OpenAI client"""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        st.error("Please set your OpenAI API key in the .env file")
        return None
    
    try:
        # Set the API key directly
        openai.api_key = api_key
        
        # Test the connection
        openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "test"}],
            max_tokens=5
        )
        return openai
    except Exception as e:
        st.error(f"Error initializing OpenAI client: {str(e)}")
        return None

def main():
    st.title("🤖 AI Chat Assistant")
    
    # Initialize OpenAI
    client = initialize_openai()
    if not client:
        st.warning("Please check your OpenAI API key and try again.")
        return

    # Display chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    # Chat input
    if prompt := st.chat_input("What would you like to know?"):
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Display user message
        with st.chat_message("user"):
            st.write(prompt)

        # Get AI response
        with st.chat_message("assistant"):
            response = client.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": m["role"], "content": m["content"]}
                    for m in st.session_state.messages
                ],
                stream=True
            )
            
            message_placeholder = st.empty()
            full_response = ""
            
            # Stream the response
            for chunk in response:
                if hasattr(chunk.choices[0], 'delta') and chunk.choices[0].delta.get('content'):
                    full_response += chunk.choices[0].delta.content
                    message_placeholder.markdown(full_response + "▌")
            message_placeholder.markdown(full_response)
            
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": full_response})

if __name__ == "__main__":
    main() 
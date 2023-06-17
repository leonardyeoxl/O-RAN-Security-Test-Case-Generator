import streamlit as st
from pathlib import Path
import base64

# Initial page config
st.set_page_config(
     page_title="O-RAN Near-RT RIC Misuse Case Scenario Generator",
     layout="wide",
     initial_sidebar_state="expanded",
)

def cs_sidebar():
    st.sidebar.header("O-RAN Near-RT RIC Misuse Case Scenario Generator")
    st.sidebar.markdown('''<small>[O-RAN-Near-RT-RIC-Misuse-Case-Scenario-Generator v0.1.0](https://github.com/leonardyeoxl/O-RAN-Near-RT-RIC-Misuse-Case-Scenario-Generator)  | Jun 2023</small>''', unsafe_allow_html=True)
    return None

def cs_body():
    with st.container():
        st.header("Build Use Case Scenario Model")
        st.subheader("Step 1: Use Case Scenario")
        st.text_area("Use Case Scenario", value="", key=None, height=350, help="use Gherkin language syntax", on_change=None, placeholder="Use Case Scenario here")
        st.subheader("Step 2: Parts-of-Speech Tagging")
        st.subheader("Step 3: Use Case Scenario Model")

    with st.container():
        st.header("Find Related Attacks")

    with st.container():
        st.header("Construct Misuse Case Scenario")
        st.subheader("Countermeasures")
        st.subheader("Suggested Prompt Design")

def main():
    cs_sidebar()
    cs_body()

    return None
    
if __name__ == "__main__":
    main()
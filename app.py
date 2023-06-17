import streamlit as st
from streamlit import components
from pathlib import Path
import base64

import spacy
from spacy import displacy
import nltk
from nltk.tokenize import TreebankWordTokenizer as twt
import spacy_transformers
import en_core_web_trf

nltk.download('averaged_perceptron_tagger')
nltk.download('universal_tagset')

def visualize_pos(text):
    pos_tags = ["PRON", "VERB", "NOUN", "ADJ", "ADP",
                "ADV", "CONJ", "DET", "NUM", "PRT"]
    
    # Tokenize text and pos tag each token
    tokens = twt().tokenize(text)
    tags = nltk.pos_tag(tokens, tagset = "universal")

    # Get start and end index (span) for each token
    span_generator = twt().span_tokenize(text)
    spans = [span for span in span_generator]

    # Create dictionary with start index, end index, 
    # pos_tag for each token
    ents = []
    for tag, span in zip(tags, spans):
        if tag[1] in pos_tags:
            ents.append({"start" : span[0], 
                         "end" : span[1], 
                         "label" : tag[1] })

    doc = {"text" : text, "ents" : ents}

    colors = {"PRON": "blueviolet",
              "VERB": "lightpink",
              "NOUN": "turquoise",
              "ADJ" : "lime",
              "ADP" : "khaki",
              "ADV" : "orange",
              "CONJ" : "cornflowerblue",
              "DET" : "forestgreen",
              "NUM" : "salmon",
              "PRT" : "yellow"}
    
    options = {"ents" : pos_tags, "colors" : colors}
    
    return displacy.render(doc,
                    style="ent",
                    jupyter=False,
                    options=options,
                    manual=True
                   )

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
        
        st.subheader("Step 1: Input Use Case Scenario")
        st.text_area("Use Case Scenario", value="", key='ucs', height=350, help="use Gherkin language syntax", on_change=None, placeholder="Use Case Scenario here")
        
        st.subheader("Step 2: Parts-of-Speech Tagging")
        ucs = st.session_state.ucs
        new_ucs = "".join([sentence.strip()+" " for sentence in ucs.split("\n")])
        ent_html = visualize_pos(new_ucs)
        st.markdown(ent_html, unsafe_allow_html=True)
        
        st.subheader("Step 3: Generate Use Case Scenario Model")
        st.subheader("Step 3.1: Select Subject")
        st.subheader("Step 3.2: Select Outcome")
        st.subheader("Step 3.3: Select Sequence(s)")

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
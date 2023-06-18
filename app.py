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

nltk.download("averaged_perceptron_tagger")
nltk.download("universal_tagset")

pos_tags = ["PRON", "VERB", "NOUN", "ADJ", "ADP", "ADV", "CONJ", "DET", "NUM", "PRT"]

NEAR_RT_RIC_ASSETS = ["RMR", "RIC MESSAGE ROUTER"]
DATA_ASSETS = ["MESSAGE", "MESSAGES"]


def gen_ents(text):
    # Tokenize text and pos tag each token
    tokens = twt().tokenize(text)
    tags = nltk.pos_tag(tokens, tagset="universal")

    # Get start and end index (span) for each token
    span_generator = twt().span_tokenize(text)
    spans = [span for span in span_generator]

    # Create dictionary with start index, end index,
    # pos_tag for each token
    ents = []
    for tag, span in zip(tags, spans):
        if tag[1] in pos_tags:
            ents.append({"start": span[0], "end": span[1], "label": tag[1]})

    return ents


def visualize_pos(text):
    ents = gen_ents(text)

    doc = {"text": text, "ents": ents}

    colors = {
        "PRON": "blueviolet",
        "VERB": "lightpink",
        "NOUN": "turquoise",
        "ADJ": "lime",
        "ADP": "khaki",
        "ADV": "orange",
        "CONJ": "cornflowerblue",
        "DET": "forestgreen",
        "NUM": "salmon",
        "PRT": "yellow",
    }

    options = {"ents": pos_tags, "colors": colors}

    return ents, displacy.render(
        doc, style="ent", jupyter=False, options=options, manual=True
    )


def gen_ent_with_word(ents, text):
    for ent in ents:
        start = ent["start"]
        end = ent["end"]
        ent["word"] = text[start:end]


def select_outcome(texts):
    index = 0
    for i in range(len(texts)):
        if texts[i].split()[0].lower() == "then":
            index = i
            break

    return index, texts[index:]


def select_sequence(texts, outcome_index):
    index = 0
    for i in range(len(texts)):
        if texts[i].split()[0].lower() == "when":
            index = i
            break

    return texts[index:outcome_index]


def select_action(ents):
    return [ents[i]["word"] for i in range(len(ents)) if ents[i]["label"] == "VERB"]


def select_data_asset(ents):
    return [
        ents[i]["word"]
        for i in range(len(ents))
        if ents[i]["label"] == "NOUN" and ents[i]["word"].upper() in DATA_ASSETS
    ]


def select_near_rt_ric_asset(ents):
    return [
        ents[i]["word"]
        for i in range(len(ents))
        if ents[i]["label"] == "NOUN" and ents[i]["word"].upper() in NEAR_RT_RIC_ASSETS
    ]


def ucs_graph(graph):
    components.v1.html(
        f"""
        <pre class="mermaid">
            {graph}
        </pre>

        <script type="module">
            import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
            mermaid.initialize({{ startOnLoad: true }});
        </script>
        """,
        scrolling=True,
        height=350,
    )


# Initial page config
st.set_page_config(
    page_title="O-RAN Near-RT RIC Misuse Case Scenario Generator",
    layout="wide",
    initial_sidebar_state="expanded",
)


def cs_sidebar():
    project_name = "O-RAN-Near-RT-RIC-Misuse-Case-Scenario-Generator"
    project_version = "v0.1.0"
    project_url = "https://github.com/leonardyeoxl/O-RAN-Near-RT-RIC-Misuse-Case-Scenario-Generator"
    date = "Jun 2023"
    st.sidebar.header(project_name)
    st.sidebar.markdown(
        f"""
        <small>[{project_name} {project_version}]({project_url})  | {date}</small>
        """,
        unsafe_allow_html=True,
    )
    return None


def cs_body():
    with st.container():
        st.header("Build Use Case Scenario Model")

        st.subheader("Step 1: Input Use Case Scenario")
        st.text_input(
            "Title",
            value="",
            key="ucstitle",
            on_change=None,
            placeholder="Use Case Scenario Title here",
        )
        st.text_area(
            "Use Case Scenario",
            value="",
            key="ucs",
            height=350,
            help="use Gherkin language syntax",
            on_change=None,
            placeholder="Use Case Scenario here",
        )

        st.subheader("Step 2: Parts-of-Speech Tagging")
        ucs = st.session_state.ucs
        new_ucs = "".join([sentence.strip() + " " for sentence in ucs.split("\n")])
        ents, ent_html = visualize_pos(new_ucs)
        st.markdown(ent_html, unsafe_allow_html=True)

        st.subheader("Step 3: Generate Use Case Scenario Model")
        if ents and new_ucs and ucs:
            gen_ent_with_word(ents, new_ucs)
            subject = st.radio(
                "Step 3.1: Select Subject",
                [ent["word"] for ent in ents if ent["label"] == "NOUN"],
            )

            outcome_index, outcomes = select_outcome(
                [sentence.strip() for sentence in ucs.split("\n")]
            )
            outcome = st.radio("Step 3.2: Select Outcome", outcomes)

            sequences = select_sequence(
                [sentence.strip() for sentence in ucs.split("\n")], outcome_index
            )
            selected_seqs = st.multiselect("Step 3.3: Select Sequences", sequences)

            selected_seqs_graph = ""
            for index in range(len(selected_seqs)):
                seq_text = selected_seqs[index]
                seq_ents = gen_ents(seq_text)
                gen_ent_with_word(seq_ents, seq_text)
                actions = select_action(seq_ents)
                data_assets = select_data_asset(seq_ents)
                near_rt_ric_assets = select_near_rt_ric_asset(seq_ents)
                selected_seqs_graph += f"D --> E{index}(Action: {','.join(actions)})\n"
                selected_seqs_graph += (
                    f"E{index} --> F{index}(Data Assets: {','.join(data_assets)})\n"
                )
                selected_seqs_graph += f"F{index} --> G{index}(Near-RT RIC Assets: {','.join(near_rt_ric_assets)})\n"

            ucs_graph(
                f"""
                graph LR
                    A({st.session_state.ucstitle})
                    A --> B(Subject: {subject})
                    A --> C(Outcome: {outcome})
                    A --> D(Sequences)
                    {selected_seqs_graph}
                """
            )

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

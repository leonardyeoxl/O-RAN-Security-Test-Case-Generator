import streamlit as st
from streamlit import components
from pathlib import Path
import base64
import json
import spacy
from spacy import displacy
import nltk
from nltk.tokenize import TreebankWordTokenizer as twt
import openai
from dotenv import load_dotenv
import os

load_dotenv()  # take environment variables from .env.

openai.api_key = os.getenv("OPENAI_API_KEY")

nltk.download("averaged_perceptron_tagger")
nltk.download("universal_tagset")

pos_tags = ["PRON", "VERB", "NOUN", "ADJ", "ADP", "ADV", "CONJ", "DET", "NUM", "PRT"]

NEAR_RT_RIC_ASSETS = ["RMR", "RIC MESSAGE ROUTER", "RMR TRANSMISSION MEDIUM", "TRANSMISSION MEDIUM"]
DATA_ASSETS = ["MESSAGE", "MESSAGES"]
ASVS = []
CAPEC = []
CWE = []
ORAN_COMPONENTS = []
ORAN_NEAR_RT_RIC = []
ORAN_SECURITY_ANALYSIS_NEAR_RT_RIC_XAPPS = []
MCS = []


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

def concat_nouns(ents):
    nouns = []
    left = 0
    word = ""
    while left < len(ents):
        while left < len(ents):
            if ents[left]["label"] != "NOUN":
                break
            word += f"{ents[left]['word']} "
            left += 1

        if word:
            nouns.append(word)
            word = ""

        left += 1

    return nouns

def concat_verbs(ents):
    verbs = []
    left = 0
    word = ""
    while left < len(ents):
        while left < len(ents):
            if ents[left]["label"] != "VERB":
                break
            word += f"{ents[left]['word']} "
            left += 1

        if word:
            verbs.append(word)
            word = ""

        left += 1

    return verbs

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

def select_data_asset(ents):
    nouns = concat_nouns(ents)
    return [
        noun.strip()
        for noun in nouns
        if noun.strip().upper() in DATA_ASSETS
    ]

def select_near_rt_ric_asset(ents):
    nouns = concat_nouns(ents)
    return [
        noun.strip()
        for noun in nouns
        if noun.strip().upper() in NEAR_RT_RIC_ASSETS
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
        height=450,
    )

def capec_related_attacks_graph(graph):
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
        height=150,
    )

def find_capec_related_attacks(data_assets, near_rt_ric_assets):
    related_attacks = set()
    for capec_key, capec_val in CAPEC.items():
        tags = [tag.lower() for tag in capec_val["tags"]]
        for data_asset in data_assets:
            if data_asset in tags:
                related_attacks.add(capec_key)
        for near_rt_ric_asset in near_rt_ric_assets:
            if near_rt_ric_asset in tags:
                related_attacks.add(capec_key)

    text = ""
    for related_attack in related_attacks:
        parent_relation = CAPEC[related_attack]['parent_relation']
        if len(parent_relation) > 0:
            for parent in parent_relation:
                if parent in CAPEC.keys():
                    text += f"{related_attack}({related_attack}:{CAPEC[related_attack]['type']}) --> {parent}({parent}: {CAPEC[parent]['type']})\n"

        child_relation = CAPEC[related_attack]['child_relation']
        if len(child_relation) > 0:
            for child in child_relation:
                if child in CAPEC.keys():
                    text += f"{related_attack}({related_attack}:{CAPEC[related_attack]['type']}) --> {child}({child}: {CAPEC[child]['type']})\n"

    if text:
        capec_related_attacks_graph(
            f"""
            graph LR
            {text}
            """
        )

    return related_attacks

def find_oran_components_related_attacks(data_assets, near_rt_ric_assets):
    related_attacks = set()
    for oran_component in ORAN_COMPONENTS:
        tags = [tag.lower() for tag in oran_component["tags"]]
        for data_asset in data_assets:
            if data_asset in tags:
                related_attacks.add(oran_component["threat_id"])
        for near_rt_ric_asset in near_rt_ric_assets:
            if near_rt_ric_asset in tags:
                related_attacks.add(oran_component["threat_id"])

    text = ""
    if text:
        ucs_graph(
            f"""
            graph LR
            {text}
            """
        )
    
    return related_attacks

def find_oran_near_rt_ric_related_attacks(data_assets, near_rt_ric_assets):
    related_attacks = set()
    for oran_near_rt_ric_key, oran_near_rt_ric_val in ORAN_NEAR_RT_RIC.items():
        tags = [tag.lower() for tag in oran_near_rt_ric_val["tags"]]
        for data_asset in data_assets:
            if data_asset in tags:
                related_attacks.add(oran_near_rt_ric_key)
        for near_rt_ric_asset in near_rt_ric_assets:
            if near_rt_ric_asset in tags:
                related_attacks.add(oran_near_rt_ric_key)

    text = ""
    if text:
        ucs_graph(
            f"""
            graph LR
            {text}
            """
        )
    
    return related_attacks

def find_oran_security_analysis_related_attacks(data_assets, near_rt_ric_assets):
    related_attacks = set()
    for oran_security_analysis_key, oran_security_analysis_val in ORAN_SECURITY_ANALYSIS_NEAR_RT_RIC_XAPPS.items():
        tags = [tag.lower() for tag in oran_security_analysis_val["tags"]]
        for data_asset in data_assets:
            if data_asset in tags:
                related_attacks.add(oran_security_analysis_key)
        for near_rt_ric_asset in near_rt_ric_assets:
            if near_rt_ric_asset in tags:
                related_attacks.add(oran_security_analysis_key)

    text = ""
    for related_attack in related_attacks:
        threat_ids = ORAN_SECURITY_ANALYSIS_NEAR_RT_RIC_XAPPS[related_attack]['key_issue_relation']
        if len(key_issue_relations) > 0:
            for threat_id in threat_ids:
                if threat_id in ORAN_NEAR_RT_RIC.keys():
                    text += f"{related_attack}({related_attack}) --> {threat_id}({threat_id}: {ORAN_NEAR_RT_RIC[threat_id]['threat_title']})\n"

    if text:
        ucs_graph(
            f"""
            graph LR
            {text}
            """
        )
    
    return related_attacks

def find_weaknesses_and_countermeasures(found_CAPEC_attacks, data_assets, near_rt_ric_assets):
    CWEs_matched = set()
    ASVSs_matched = set()
    for found_CAPEC_attack in found_CAPEC_attacks:
        if CAPEC[found_CAPEC_attack]:
            related_weaknesses = CAPEC[found_CAPEC_attack]["related_weaknesses"]
            if related_weaknesses:
                for related_weakness in related_weaknesses:
                    if CWE[related_weakness]:
                        CWEs_matched.add(related_weakness)

    parent_child_matched_CWEs = set()
    # find related CWEs by matched CWEs
    for CWE_matched in CWEs_matched:
        if CWE[CWE_matched]:
            parents_relation_to = CWE[CWE_matched]["parent_relation_to"]
            for parent in parents_relation_to:
                if CWE[parent]:
                    parent_child_matched_CWEs.add(parent)
            
            children_relation_to = CWE[CWE_matched]["child_relation_to"]
            for child in children_relation_to:
                if CWE[child]:
                    parent_child_matched_CWEs.add(child)

    CWEs_matched = CWEs_matched.union(parent_child_matched_CWEs)

    for CWE_matched in CWEs_matched:
        for ASVS_item_key, ASVS_item_val in ASVS.items():
            if CWE_matched in ASVS_item_val["related_cwe_ids"]:
                ASVSs_matched.add(ASVS_item_key)

    return CWEs_matched, ASVSs_matched

def gen_prompt(
    use_case_scenario,
    use_case_scenario_title,
    CAPEC,
    CWE,
    SWG_O_RAN_Components_Threat_Model,
    SWG_O_RAN_Near_RT_RIC_Components_Threat_Model,
    SWG_Security_Analysis_for_Near_RT_RIC_and_xApps,
    Examples_Misuse_Case_Scenario,
):
    NONE = "None"
    system = "You are a cyber security testing expert. You are familiar with writing security test cases. Also, you are familiar with CAPEC, CWE and SWG O-RAN Security.\n\n"
    system += f"Use Case Scenario Title,\n{use_case_scenario_title}\n\n"
    system += f"Use Case Scenario in Gherkin language syntax,\n{use_case_scenario}\n\n"
    system += f"CAPEC,\n{CAPEC}\n\n"
    system += f"CWEs,\n{CWE}\n\n"
    system += f"SWG O-RAN Components Threat Model,\n{SWG_O_RAN_Components_Threat_Model if SWG_O_RAN_Components_Threat_Model else NONE}\n\n"
    system += f"SWG O-RAN Near-RT RIC Component Threat Model,\n{SWG_O_RAN_Near_RT_RIC_Components_Threat_Model if SWG_O_RAN_Near_RT_RIC_Components_Threat_Model else NONE}\n\n"
    system += f"SWG Security Analysis for Near-RT RIC and xApps,\n{SWG_Security_Analysis_for_Near_RT_RIC_and_xApps if SWG_Security_Analysis_for_Near_RT_RIC_and_xApps else NONE}\n\n"
    system += f"Examples of Misuse Case Scenario in Gherkin language syntax,\n{Examples_Misuse_Case_Scenario if Examples_Misuse_Case_Scenario else NONE}\n\n"
    user = f"Construct a Misuse Case Scenario in Gherkin language syntax from above Use Case Scenario, CAPEC, CWEs, SWG O-RAN Components Threat Model (if not none), SWG O-RAN Near-RT RIC Component Threat Model (if not none) and SWG Security Analysis for Near-RT RIC and xApps (if not none)."
    return system, user, system+user


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

def read_data():
    global ASVS, CAPEC, CWE, ORAN_COMPONENTS, ORAN_NEAR_RT_RIC, ORAN_SECURITY_ANALYSIS_NEAR_RT_RIC_XAPPS, MCS

    with open('./data/asvs.json', "r") as asvs_file:
        ASVS = json.load(asvs_file)
    
    with open('./data/capec.json', "r") as capec_file:
        CAPEC = json.load(capec_file)

    with open('./data/cwe.json', "r") as cwe_file:
        CWE = json.load(cwe_file)

    with open('./data/oran-components.json', "r") as oran_components_file:
        ORAN_COMPONENTS = json.load(oran_components_file)
    
    with open('./data/oran-near-rt-ric.json', "r") as oran_near_rt_ric_file:
        ORAN_NEAR_RT_RIC = json.load(oran_near_rt_ric_file)
    
    with open('./data/oran-security-analysis.json', "r") as oran_security_analysis_file:
        ORAN_SECURITY_ANALYSIS_NEAR_RT_RIC_XAPPS = json.load(oran_security_analysis_file)

    with open('./data/misuse-case-scenario-examples.json', "r") as mcs_examples_file:
        MCS = json.load(mcs_examples_file)

def cs_body():
    with st.container():
        st.header("1. Build Use Case Scenario Model")

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
        selected_seqs = []
        if ents and new_ucs and ucs:
            gen_ent_with_word(ents, new_ucs)
            nouns = concat_nouns(ents)
            subject = st.radio(
                "Step 3.1: Select Subject",
                [noun.strip() for noun in set(nouns)],
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
            data_assets = []
            near_rt_ric_assets = []
            for index in range(len(selected_seqs)):
                seq_text = selected_seqs[index]
                seq_ents = gen_ents(seq_text)
                gen_ent_with_word(seq_ents, seq_text)
                actions = concat_verbs(seq_ents)
                data_assets = select_data_asset(seq_ents)
                near_rt_ric_assets = select_near_rt_ric_asset(seq_ents)
                selected_seqs_graph += f"D --> E{index}(Action: {','.join(actions)})\n"
                selected_seqs_graph += (
                    f"E{index} --> F{index}(Data Assets: {','.join(data_assets)})\n"
                )
                selected_seqs_graph += f"F{index} --> G{index}(Near-RT RIC Assets: {','.join(near_rt_ric_assets)})\n"

            ucs_graph(
                f"""
                graph TD
                    A({st.session_state.ucstitle})
                    A --> B(Subject: {subject})
                    A --> C(Outcome: {outcome})
                    A --> D(Sequences)
                    {selected_seqs_graph}
                """
            )

            st.header("2. Find Related Attacks")
            capec_related_attacks = set()
            oran_components_related_attacks = set()
            oran_near_rt_ric_related_attacks = set()
            oran_security_analysis_related_attacks = set()
            capec_related_attacks = find_capec_related_attacks(data_assets, near_rt_ric_assets)
            oran_components_related_attacks = find_oran_components_related_attacks(data_assets, near_rt_ric_assets)
            oran_near_rt_ric_related_attacks = find_oran_near_rt_ric_related_attacks(data_assets, near_rt_ric_assets)
            oran_security_analysis_related_attacks = find_oran_security_analysis_related_attacks(data_assets, near_rt_ric_assets)

            st.subheader("CAPEC Related Attacks")
            if capec_related_attacks:
                for capec_related_attack in capec_related_attacks:
                    st.write(capec_related_attack)
            else:
                st.write("There are no CAPEC Related Attacks found.")

            st.subheader("O-RAN Components Related Attacks")
            if oran_components_related_attacks:
                for oran_components_related_attack in oran_components_related_attacks:
                    st.write(oran_components_related_attack)
            else:
                st.write("There are no O-RAN Components Related Attacks found.")

            st.subheader("O-RAN Near-RT RIC Related Attacks")
            if oran_near_rt_ric_related_attacks:
                for oran_near_rt_ric_related_attack in oran_near_rt_ric_related_attacks:
                    st.write(oran_near_rt_ric_related_attack)
            else:
                st.write("There are no O-RAN Near-RT RIC Related Attacks found.")

            st.subheader("O-RAN Security Analysis on Near-RT RIC and xApps Related Attacks")
            if oran_security_analysis_related_attacks:
                for oran_security_analysis_related_attack in oran_security_analysis_related_attacks:
                    st.write(oran_security_analysis_related_attack)
            else:
                st.write("There are no O-RAN Security Analysis on Near-RT RIC and xApps Related Attacks found.")


            st.header("3. Construct Misuse Case Scenario")
            CWEs_matched, ASVSs_matched = find_weaknesses_and_countermeasures(
                capec_related_attacks,
                data_assets,
                near_rt_ric_assets
            )
            st.subheader("CWE")
            if CWEs_matched:
                for CWE_matched in CWEs_matched:
                    CWE_id = CWE[CWE_matched]["cwe_id"]
                    CWE_type = CWE[CWE_matched]["type"]
                    CWE_description = CWE[CWE_matched]["description"]
                    st.write(f"ID: {CWE_id}")
                    st.write(f"Type: {CWE_type}")
                    st.write(f"Description: {CWE_description}\n")
                    st.write("")
            else:
                st.write("CWE not found")

            st.subheader("ASVS Countermeasures")
            if ASVSs_matched:
                for ASVS_matched in ASVSs_matched:
                    ASVS_id = ASVS[ASVS_matched]["asvs_id"]
                    ASVS_type = ASVS[ASVS_matched]["type"]
                    ASVS_description = ASVS[ASVS_matched]["description"]
                    st.write(f"ID: {ASVS_id}")
                    st.write(f"Type: {ASVS_type}")
                    st.write(f"Description: {ASVS_description}\n")
                    st.write("")
            else:
                st.write("ASVS Countermeasures not found")

            st.subheader("O-RAN Near-RT RIC Countermeasures")
            st.write("There are no O-RAN Near-RT RIC Countermeasures found.")

            st.subheader("O-RAN Near-RT RIC xApp Countermeasures")
            st.write("There are no O-RAN Near-RT RIC xApp Countermeasures found.")

            st.subheader("Suggested Prompt Design")
            CAPEC_prompt = ""
            for capec_related_attack in capec_related_attacks:
                CAPEC_type = CAPEC[capec_related_attack]["type"]
                CAPEC_description = CAPEC[capec_related_attack]["description"]
                CAPEC_prompt += f"{capec_related_attack}: {CAPEC_type}. {CAPEC_description}\n"

            CWE_prompt = ""
            for CWE_matched in CWEs_matched:
                CWE_id = CWE[CWE_matched]["cwe_id"]
                CWE_type = CWE[CWE_matched]["type"]
                CWE_description = CWE[CWE_matched]["description"]
                CWE_prompt += f"{CWE_id}: {CWE_type}. {CWE_description}\n"

            Examples_Misuse_Case_Scenario = ""
            for scenario in MCS:
                Examples_Misuse_Case_Scenario += scenario

            system, user, prompt = gen_prompt(
                st.session_state.ucs,
                st.session_state.ucstitle,
                CAPEC_prompt,
                CWE_prompt,
                oran_components_related_attacks,
                oran_near_rt_ric_related_attacks,
                oran_security_analysis_related_attacks,
                Examples_Misuse_Case_Scenario,
            )
            st.text_area(label="prompt_design", height=850, value=prompt, disabled=True)

            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user}
                ]
            )

            st.text_area(label="gpt_completion", height=850, value=completion.choices[0].message, disabled=True)


def main():
    read_data()
    cs_sidebar()
    cs_body()

    return None


if __name__ == "__main__":
    main()

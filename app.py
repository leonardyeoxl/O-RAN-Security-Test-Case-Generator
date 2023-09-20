import streamlit as st
from streamlit import components
from pathlib import Path
import base64
import json
from spacy import displacy
import nltk
from nltk.tokenize import TreebankWordTokenizer as twt
import openai
from dotenv import load_dotenv
import os
import csv
import re
from itertools import islice
import time

load_dotenv()  # take environment variables from .env.

openai.api_key = st.secrets['api_key']

nltk.download("averaged_perceptron_tagger")
nltk.download("universal_tagset")

st.session_state.pos_tags = ["PRON", "VERB", "NOUN", "ADJ", "ADP", "ADV", "CONJ", "DET", "NUM", "PRT"]

st.session_state.NEAR_RT_RIC_ASSETS = ["RMR", "RIC MESSAGE ROUTER", "RMR LIBRARY", "LIBRARY"]
st.session_state.DATA_ASSETS = ["MESSAGE", "MESSAGES"]
st.session_state.ASVS = []
st.session_state.CAPEC = {}
st.session_state.CWE = []
st.session_state.ORAN_COMPONENTS = []
st.session_state.ORAN_NEAR_RT_RIC = {}
st.session_state.ORAN_SECURITY_ANALYSIS_NEAR_RT_RIC_XAPPS = {}
st.session_state.MCS = []

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
        if tag[1] in st.session_state.pos_tags:
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

    options = {"ents": st.session_state.pos_tags, "colors": colors}

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
        if noun.strip().upper() in st.session_state.DATA_ASSETS
    ]

def select_near_rt_ric_asset(ents):
    nouns = concat_nouns(ents)
    return [
        noun.strip()
        for noun in nouns
        if noun.strip().upper() in st.session_state.NEAR_RT_RIC_ASSETS
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

def application_test_case_to_ucs(app_source_code, use_case_scenario_examples):
    system = "You are a cyber security testing expert. You are familiar with writing security test cases and programming.\n\n"
    user = f"Given these application source code,\n{app_source_code}\n\n"
    # user += f"Given these examples of Use Case Scenario in Gherkin language syntax,\n{use_case_scenario_examples}\n\n"
    # user += 'Understand the application source code and examples of Use Case Scenario in Gherkin language syntax, write only 1 Use Case Scenario based on the given application source code.'
    user += 'Understand the application source code, write only 1 Use Case Scenario in Gherkin language syntax based on the given application source code.'

    completion = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        temperature=0
    )
    llm_contents = completion.choices[0].message["content"]
    pattern = r"Scenario: [^\n]*\n((?:    [^\n]*\n)*)"
    match = re.search(pattern, llm_contents, re.DOTALL)
    if match:
        return match.group(1), llm_contents
    return "", llm_contents

def ucs_to_ucs_title(ucs):
    system = "You are a cyber security testing expert. You are familiar with writing security test cases and programming.\n\n"
    user = f"Given this Use Case Scenario in Gherkin language syntax,\n{ucs}\n\n"
    # user += f"Given these examples of Use Case Scenario title,\n{use_case_scenario_title_examples}\n\n"
    # user += 'Understand the application source code and examples of Use Case Scenario title, write only 1 Use Case Scenario title based on the given application source code.'
    user += 'Understand the Use Case Scenario in Gherkin language syntax, write only 1 Use Case Scenario title based on the given Use Case Scenario.'

    completion = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        temperature=0
    )
    llm_contents = completion.choices[0].message["content"]
    pattern = r"Scenario: ([^\n]*)"
    match = re.search(pattern, llm_contents, re.DOTALL)
    if match:
        return match.group(1), llm_contents
    return "", llm_contents

def find_capec_related_attacks(data_assets, near_rt_ric_assets, actions):
    related_attacks = set()
    for capec_key, capec_val in CAPEC.items():
        tags = [tag.lower() for tag in capec_val["tags"]]
        for action in actions:
            if action in tags:
                related_attacks.add(capec_key)
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

def find_capec_related_attacks_llm(use_case_scenario_title, use_case_scenario_description, capec_attack_patterns):
    related_attacks = set()

    system = "You are a cyber security testing expert. You are familiar with writing security test cases. Also, you are familiar with CAPEC.\n\n"
    user = f"Given this Use Case Scenario Title,\n{use_case_scenario_title}\n\n"
    user += f"Given this Use Case Scenario Description,\n{use_case_scenario_description}\n\n"
    user += f"Given these CAPEC attack patterns,\n{capec_attack_patterns}\n\n"
    user += 'From your understanding of the Use Case Scenario Title and Use Case Scenario Description and CAPEC attack patterns, find CAPEC attack pattern(s) that have high relevance and high match with the threat model(s) with confidence of above 98%% only. Also, for the found and matched attack pattern(s), give an explanation and confidence score as to why the attack pattern is found and matched. Do not include any explanations, only provide a RFC8259 compliant JSON response following this format without deviation.\n{"content": [{"capec_id":"", "explanation":"", "confidence":""}]}\nThe JSON response:'

    completion = openai.ChatCompletion.create(
        # model="gpt-3.5-turbo-16k",
        model="gpt-4",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        temperature=0
    )
    llm_contents = json.loads(completion.choices[0].message["content"])

    for content in llm_contents["content"]:
        id_and_explain_map = {"capec_id": content["capec_id"], "explanation":content["explanation"], "confidence":content["confidence"]}
        related_attacks.add(tuple(id_and_explain_map.items()))

    text = ""
    for related_attack in related_attacks:
        related_capec_id = dict(related_attack)["capec_id"].strip()
        if st.session_state.CAPEC.get(related_capec_id) is None:
            continue
        
        parent_relation = st.session_state.CAPEC[related_capec_id]['parent_relation']
        if len(parent_relation) > 0:
            for parent in parent_relation:
                if parent in st.session_state.CAPEC.keys():
                    text += f"{related_capec_id}({related_capec_id}:{st.session_state.CAPEC[related_capec_id]['type']}) --> {parent}({parent}: {st.session_state.CAPEC[parent]['type']})\n"

        child_relation = st.session_state.CAPEC[related_capec_id]['child_relation']
        if len(child_relation) > 0:
            for child in child_relation:
                if child in st.session_state.CAPEC.keys():
                    text += f"{related_capec_id}({related_capec_id}:{st.session_state.CAPEC[related_capec_id]['type']}) --> {child}({child}: {st.session_state.CAPEC[child]['type']})\n"

    # if text:
    #     capec_related_attacks_graph(
    #         f"""
    #         graph LR
    #         {text}
    #         """
    #     )

    return related_attacks

def find_oran_components_related_attacks(data_assets, near_rt_ric_assets, actions):
    related_attacks = set()
    for oran_component in ORAN_COMPONENTS:
        tags = [tag.lower() for tag in oran_component["tags"]]
        for action in actions:
            if action in tags:
                related_attacks.add(oran_component["threat_id"])
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

def find_oran_components_related_attacks_llm(use_case_scenario_title, use_case_scenario_description, oran_components_attack_patterns):
    related_attacks = set()

    system = "You are a cyber security testing expert. You are familiar with writing security test cases. Also, you are familiar with SWG O-RAN Security.\n\n"
    user = f"Given this Use Case Scenario Title,\n{use_case_scenario_title}\n\n"
    user += f"Given this Use Case Scenario Description,\n{use_case_scenario_description}\n\n"
    user += f"Given these OpenRAN attack patterns,\n{oran_components_attack_patterns}\n\n"
    user += 'From your understanding of the Use Case Scenario Title and Use Case Scenario Description and OpenRAN attack patterns, find OpenRAN attack pattern(s) that have high relevance and high match with the threat model(s) with confidence of above 95%% only. Also, for the found and matched attack pattern(s), give an explanation and confidence score as to why the attack pattern is found and matched. Do not include any explanations, only provide a RFC8259 compliant JSON response following this format without deviation.\n{"content": [{"threat_id":"", "explanation":"", "confidence":""}]}\nThe JSON response:'

    completion = openai.ChatCompletion.create(
        model="gpt-3.5-turbo-16k",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        temperature=0
    )
    llm_contents = json.loads(completion.choices[0].message["content"])

    for content in llm_contents["content"]:
        id_and_explain_map = {"threat_id": content["threat_id"], "explanation":content["explanation"], "confidence":content["confidence"]}
        related_attacks.add(tuple(id_and_explain_map.items()))

    return related_attacks

def find_oran_near_rt_ric_related_attacks(data_assets, near_rt_ric_assets, actions):
    related_attacks = set()
    for oran_near_rt_ric_key, oran_near_rt_ric_val in ORAN_NEAR_RT_RIC.items():
        tags = [tag.lower() for tag in oran_near_rt_ric_val["tags"]]
        for action in actions:
            if action in tags:
                related_attacks.add(oran_near_rt_ric_key)
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

def find_oran_near_rt_ric_related_attacks_llm(use_case_scenario_title, use_case_scenario_description, oran_near_rt_ric_attack_patterns):
    related_attacks = set()

    system = "You are a cyber security testing expert. You are familiar with writing security test cases. Also, you are familiar with SWG O-RAN Security.\n\n"
    user = f"Given this Use Case Scenario Title,\n{use_case_scenario_title}\n\n"
    user += f"Given this Use Case Scenario Description,\n{use_case_scenario_description}\n\n"
    user += f"Given these OpenRAN Near-RT RIC attack patterns,\n{oran_near_rt_ric_attack_patterns}\n\n"
    user += 'From your understanding of the Use Case Scenario Title and Use Case Scenario Description and OpenRAN Near-RT RIC attack patterns, find OpenRAN Near-RT RIC attack pattern(s) that have high relevance and high match with the threat model(s) with confidence of above 95%% only. Also, for the found and matched attack pattern(s), give an explanation and confidence score as to why the attack pattern is found and matched. Do not include any explanations, only provide a RFC8259 compliant JSON response following this format without deviation.\n{"content": [{"threat_id":"", "explanation":"", "confidence":""}]}\nThe JSON response:'

    completion = openai.ChatCompletion.create(
        model="gpt-3.5-turbo-16k",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        temperature=0
    )
    llm_contents = json.loads(completion.choices[0].message["content"])

    for content in llm_contents["content"]:
        id_and_explain_map = {"threat_id": content["threat_id"], "explanation":content["explanation"], "confidence":content["confidence"]}
        related_attacks.add(tuple(id_and_explain_map.items()))

    return related_attacks

def find_oran_security_analysis_related_attacks(data_assets, near_rt_ric_assets, actions):
    related_attacks = set()
    for oran_security_analysis_key, oran_security_analysis_val in ORAN_SECURITY_ANALYSIS_NEAR_RT_RIC_XAPPS.items():
        tags = [tag.lower() for tag in oran_security_analysis_val["tags"]]
        for action in actions:
            if action in tags:
                related_attacks.add(oran_security_analysis_key)
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

def find_oran_security_analysis_related_attacks_llm(use_case_scenario_title, use_case_scenario_description, oran_security_analysis_attack_patterns):
    related_attacks = set()

    system = "You are a cyber security testing expert. You are familiar with writing security test cases. Also, you are familiar with SWG O-RAN Security.\n\n"
    user = f"Given this Use Case Scenario Title,\n{use_case_scenario_title}\n\n"
    user += f"Given this Use Case Scenario Description,\n{use_case_scenario_description}\n\n"
    user += f"Given these OpenRAN Near-RT RIC and xApps attack patterns,\n{oran_security_analysis_attack_patterns}\n\n"
    user += 'From your understanding of the Use Case Scenario Title and Use Case Scenario Description and OpenRAN Near-RT RIC and xApps attack patterns, find OpenRAN Near-RT RIC and xApps attack pattern(s) that have high relevance and high match with the threat model(s) with confidence of above 95%% only. Also, for the found and matched attack pattern(s), give an explanation and confidence score as to why the attack pattern is found and matched. Do not include any explanations, only provide a RFC8259 compliant JSON response following this format without deviation.\n{"content": [{"threat_id":"", "explanation":"", "confidence":""}]}\nThe JSON response:'

    completion = openai.ChatCompletion.create(
        model="gpt-3.5-turbo-16k",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        temperature=0
    )
    llm_contents = json.loads(completion.choices[0].message["content"])

    for content in llm_contents["content"]:
        id_and_explain_map = {"threat_id": content["threat_id"], "explanation":content["explanation"], "confidence":content["confidence"]}
        related_attacks.add(tuple(id_and_explain_map.items()))

    return related_attacks

def find_weaknesses_and_countermeasures(found_CAPEC_attacks):
    CWEs_matched = set()
    ASVSs_matched = set()
    for found_CAPEC_attack in found_CAPEC_attacks:
        capec_id = dict(found_CAPEC_attack)["capec_id"]
        if capec_id in st.session_state.CAPEC.keys():
            related_weaknesses = st.session_state.CAPEC[capec_id]["related_weaknesses"]
            if related_weaknesses:
                for related_weakness in related_weaknesses:
                    if related_weakness in st.session_state.CWE.keys():
                        if st.session_state.CWE[related_weakness]:
                            CWEs_matched.add(related_weakness)

    # find related CWEs by matched CWEs
    # parent_child_matched_CWEs = set()
    # for CWE_matched in CWEs_matched:
    #     if CWE[CWE_matched]:
    #         parents_relation_to = CWE[CWE_matched]["parent_relation_to"]
    #         for parent in parents_relation_to:
    #             if CWE[parent]:
    #                 parent_child_matched_CWEs.add(parent)
            
    #         children_relation_to = CWE[CWE_matched]["child_relation_to"]
    #         for child in children_relation_to:
    #             if CWE[child]:
    #                 parent_child_matched_CWEs.add(child)

    # CWEs_matched = CWEs_matched.union(parent_child_matched_CWEs)

    for CWE_matched in CWEs_matched:
        for ASVS_item_key, ASVS_item_val in st.session_state.ASVS.items():
            if CWE_matched in ASVS_item_val["related_cwe_ids"]:
                ASVSs_matched.add(ASVS_item_key)

    return CWEs_matched, ASVSs_matched

def read_capec_data():
    CAPEC = {}
    with open('./data/capec_1000.csv', 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            id = row["ID"]
            name = row["Name"]
            description = row["Description"]
            related_weaknesses = row["Related Weaknesses"]
            related_attack_patterns = row["Related Attack Patterns"]
            child_related_attack_patterns_matches = re.findall(
                r"ChildOf:CAPEC ID:(\d+)",
                related_attack_patterns
            )
            CAPEC[f"CAPEC-{id}"] = {
                "capec_id": f"CAPEC-{id}",
                "description": description,
                "type": name,
                "related_weaknesses": [f"CWE-{rw}" for rw in related_weaknesses.replace("-","").split("::")],
                "child_relation": [f"CAPEC-{capec_id}" for capec_id in child_related_attack_patterns_matches],
                "parent_relation": set()
            }
    
    for key, val in CAPEC.items():
        for child in val["child_relation"]:
            if child in CAPEC.keys():
                existing = CAPEC[child]
                existing["parent_relation"].add(key)
                CAPEC[child] = existing
    
    for key, val in CAPEC.items():
        val["parent_relation"] = list(val["parent_relation"])
    
    st.session_state.CAPEC = CAPEC

def read_cwe_data():
    CWE = {}
    with open('./data/cwe_699.csv', 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            id = row["CWE-ID"]
            name = row["Name"]
            description = row["Description"]
            related_weaknesses = row["Related Weaknesses"]
            child_related_weaknesses_matches = re.findall(
                r"ChildOf:CWE ID:(\d+)",
                related_weaknesses
            )
            CWE[f"CWE-{id}"] = {
                "cwe_id": f"CWE-{id}",
                "description": description,
                "type": name,
                "child_relation": [f"CWE-{cwe_id}" for cwe_id in child_related_weaknesses_matches],
                "parent_relation": set()
            }
    
    for key, val in CWE.items():
        for child in val["child_relation"]:
            if child in CWE.keys():
                existing = CWE[child]
                existing["parent_relation"].add(key)
                CWE[child] = existing
    
    for key, val in CWE.items():
        val["parent_relation"] = list(val["parent_relation"])
    
    st.session_state.CWE = CWE

def seperate_capec():
    def chunks(data, SIZE=10000):
        it = iter(data)
        for i in range(0, len(data), SIZE):
            yield {k:data[k] for k in islice(it, SIZE)}


    capec_attack_patterns_list = []
    for item in chunks(st.session_state.CAPEC, 50):
        capec_attack_patterns_temp = ""
        for CAPEC_atk_pattern_id, CAPEC_atk_pattern in item.items():
            capec_attack_patterns_temp += f"CAPEC id: {CAPEC_atk_pattern_id}: CAPEC title: {CAPEC_atk_pattern['type']}. CAPEC description: {CAPEC_atk_pattern['description']}\n"
        capec_attack_patterns_list.append(capec_attack_patterns_temp)

    return capec_attack_patterns_list

def gen_prompt(
    use_case_scenario,
    use_case_scenario_title,
    CAPEC,
    CWE,
    ASVS,
    SWG_O_RAN_Components_Threat_Model,
    SWG_O_RAN_Near_RT_RIC_Components_Threat_Model,
    SWG_Security_Analysis_for_Near_RT_RIC_and_xApps,
    SWG_Security_Analysis_for_Near_RT_RIC_and_xApps_mitigations,
    Examples_Misuse_Case_Scenario,
):
    NONE = "None"
    system = "You are a cyber security testing expert. You are familiar with writing security test cases. Also, you are familiar with CAPEC, CWE and SWG O-RAN Security.\n\n"
    user = f"Use Case Scenario Title,\n{use_case_scenario_title}\n\n"
    user += f"Use Case Scenario in Gherkin language syntax,\n{use_case_scenario}\n\n"
    user += f"CAPEC,\n{CAPEC}\n\n"
    user += f"CWE mitigations or solutions,\n{CWE}\n\n"
    user += f"ASVS mitigations or solutions,\n{ASVS}\n\n"
    user += f"SWG O-RAN Components Threat Model,\n{SWG_O_RAN_Components_Threat_Model if SWG_O_RAN_Components_Threat_Model else NONE}\n\n"
    user += f"SWG O-RAN Near-RT RIC Component Threat Model,\n{SWG_O_RAN_Near_RT_RIC_Components_Threat_Model if SWG_O_RAN_Near_RT_RIC_Components_Threat_Model else NONE}\n\n"
    user += f"SWG Security Analysis for Near-RT RIC and xApps,\n{SWG_Security_Analysis_for_Near_RT_RIC_and_xApps if SWG_Security_Analysis_for_Near_RT_RIC_and_xApps else NONE}\n\n"
    user += f"SWG Security Analysis for Near-RT RIC and xApps mitigations or solutions,\n{SWG_Security_Analysis_for_Near_RT_RIC_and_xApps_mitigations}\n\n"
    user += "Purpose of Misuse Case Scenario?\n- provides additional information about the potential threats and security controls that security engineers or researchers can use to counter those threats. \n\n"
    user += "How to construct a Misuse Case Scenario in Gherkin language syntax?\n- provide additional information about the potential threats and security controls that security engineers or researchers can use to counter those threats. \n- For constructing the When statement, use the threat patterns from CAPEC, SWG O-RAN Components Threat Model, SWG O-RAN Near-RT RIC Component Threat Model and SWG Security Analysis for Near-RT RIC and xApps. \n- For constructing the Then statement, use CWE mitigations or solutions, ASVS mitigations or solutions and SWG Security Analysis for Near-RT RIC and xApps mitigations or solutions.\n\n"
    user += f"Examples of Misuse Case Scenario in Gherkin language syntax,\n{Examples_Misuse_Case_Scenario if Examples_Misuse_Case_Scenario else NONE}\n\n"
    user += 'From your understanding of how to construct a Misuse Case Scenario and the given examples of Misuse Case Scenario, propose best 5 unique Misuse Case Scenarios in Gherkin language syntax from above Use Case Scenario, CAPEC, CWEs, SWG O-RAN Components Threat Model (if not none), SWG O-RAN Near-RT RIC Component Threat Model (if not none) and SWG Security Analysis for Near-RT RIC and xApps (if not none). Output this in a JSON array of objects, the object must follow in this format, {"misuse_case_scenario":""}. The misuse case scenarios proposed should not be exactly the same as the use case scenario.'
    return system, user, system+user

def gen_prompt(
    use_case_scenario,
    use_case_scenario_title,
    CAPEC,
    CWE,
    ASVS,
    SWG_O_RAN_Components_Threat_Model,
    SWG_O_RAN_Near_RT_RIC_Components_Threat_Model,
    SWG_Security_Analysis_for_Near_RT_RIC_and_xApps,
    SWG_Security_Analysis_for_Near_RT_RIC_and_xApps_mitigations,
    Examples_Misuse_Case_Scenario,
):
    NONE = "None"
    system = "You are a cyber security testing expert. You are familiar with writing security test cases. Also, you are familiar with CAPEC, CWE and SWG O-RAN Security.\n\n"
    user = f"Use Case Scenario Title,\n{use_case_scenario_title}\n\n"
    user += f"Use Case Scenario in Gherkin language syntax,\n{use_case_scenario}\n\n"
    user += f"CAPEC,\n{CAPEC}\n\n"
    user += f"CWE mitigations or solutions,\n{CWE}\n\n"
    user += f"ASVS mitigations or solutions,\n{ASVS}\n\n"
    user += f"SWG O-RAN Components Threat Model,\n{SWG_O_RAN_Components_Threat_Model if SWG_O_RAN_Components_Threat_Model else NONE}\n\n"
    user += f"SWG O-RAN Near-RT RIC Component Threat Model,\n{SWG_O_RAN_Near_RT_RIC_Components_Threat_Model if SWG_O_RAN_Near_RT_RIC_Components_Threat_Model else NONE}\n\n"
    user += f"SWG Security Analysis for Near-RT RIC and xApps,\n{SWG_Security_Analysis_for_Near_RT_RIC_and_xApps if SWG_Security_Analysis_for_Near_RT_RIC_and_xApps else NONE}\n\n"
    user += f"SWG Security Analysis for Near-RT RIC and xApps mitigations or solutions,\n{SWG_Security_Analysis_for_Near_RT_RIC_and_xApps_mitigations}\n\n"
    user += "Purpose of Misuse Case Scenario?\n- provides additional information about the potential threats and security controls that security engineers or researchers can use to counter those threats. \n\n"
    user += "How to construct a Misuse Case Scenario in Gherkin language syntax?\n- provide additional information about the potential threats and security controls that security engineers or researchers can use to counter those threats. \n- For constructing the When statement, use the threat patterns from CAPEC, SWG O-RAN Components Threat Model, SWG O-RAN Near-RT RIC Component Threat Model and SWG Security Analysis for Near-RT RIC and xApps. \n- For constructing the Then statement, use CWE mitigations or solutions, ASVS mitigations or solutions and SWG Security Analysis for Near-RT RIC and xApps mitigations or solutions.\n\n"
    user += f"Examples of Misuse Case Scenario in Gherkin language syntax,\n{Examples_Misuse_Case_Scenario if Examples_Misuse_Case_Scenario else NONE}\n\n"
    user += 'From your understanding of how to construct a Misuse Case Scenario and the given examples of Misuse Case Scenario, propose best 5 unique Misuse Case Scenarios in Gherkin language syntax from above Use Case Scenario, CAPEC, CWEs, SWG O-RAN Components Threat Model (if not none), SWG O-RAN Near-RT RIC Component Threat Model (if not none) and SWG Security Analysis for Near-RT RIC and xApps (if not none). Output this in a JSON array of objects, the object must follow in this format, {"misuse_case_scenario":""}. The misuse case scenarios proposed should not be exactly the same as the use case scenario.'
    return system, user, system+user

def gen_prompt_no_oran(
    use_case_scenario,
    use_case_scenario_title,
    CAPEC,
    CWE,
    ASVS,
    Examples_Misuse_Case_Scenario,
):
    NONE = "None"
    system = "You are a cyber security testing expert. You are familiar with writing security test cases. Also, you are familiar with CAPEC and CWE Security.\n\n"
    user = f"Use Case Scenario Title,\n{use_case_scenario_title}\n\n"
    user += f"Use Case Scenario in Gherkin language syntax,\n{use_case_scenario}\n\n"
    user += f"CAPEC,\n{CAPEC}\n\n"
    user += f"CWE mitigations or solutions,\n{CWE}\n\n"
    user += f"ASVS mitigations or solutions,\n{ASVS}\n\n"
    user += "Purpose of Misuse Case Scenario?\n- provides additional information about the potential threats and security controls that security engineers or researchers can use to counter those threats. \n\n"
    user += "How to construct a Misuse Case Scenario in Gherkin language syntax?\n- provide additional information about the potential threats and security controls that security engineers or researchers can use to counter those threats. \n- For constructing the When statement, use the threat patterns from CAPEC.\n- For constructing the Then statement, use CWE mitigations or solutions, ASVS mitigations or solutions.\n\n"
    user += f"Examples of Misuse Case Scenario in Gherkin language syntax,\n{Examples_Misuse_Case_Scenario if Examples_Misuse_Case_Scenario else NONE}\n\n"
    user += 'From your understanding of how to construct a Misuse Case Scenario and the given examples of Misuse Case Scenario, propose best 5 unique Misuse Case Scenarios in Gherkin language syntax from above Use Case Scenario, CAPEC and CWEs. Output this in a JSON array of objects, the object must follow in this format, {"misuse_case_scenario":""}. The misuse case scenarios proposed should not be exactly the same as the use case scenario.'
    return system, user, system+user

# Initial page config
st.set_page_config(
    page_title="O-RAN Security Test Case Generator",
    layout="wide",
    initial_sidebar_state="expanded",
)

def cs_sidebar():
    project_name = "O-RAN-Security-Test-Case-Generator"
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
    with open('./data/asvs.json', "r") as asvs_file:
        st.session_state.ASVS = json.load(asvs_file)

    read_capec_data()
    read_cwe_data()

    with open('./data/oran-components.json', "r") as oran_components_file:
        st.session_state.ORAN_COMPONENTS = json.load(oran_components_file)
    
    with open('./data/oran-near-rt-ric.json', "r") as oran_near_rt_ric_file:
        st.session_state.ORAN_NEAR_RT_RIC = json.load(oran_near_rt_ric_file)
    
    with open('./data/oran-security-analysis.json', "r") as oran_security_analysis_file:
        st.session_state.ORAN_SECURITY_ANALYSIS_NEAR_RT_RIC_XAPPS = json.load(oran_security_analysis_file)

    with open('./data/misuse-case-scenario-examples.json', "r") as mcs_examples_file:
        st.session_state.MCS = json.load(mcs_examples_file)

def start_section():
    # First section with a form
    st.title("1. Build Use Case Scenario Model")
    
    with st.form(key='start_section'):
        st.header("Step 1. Application Source Code")

        if 'ucs_from_llm' not in st.session_state:
            st.session_state.ucs_from_llm = ""

        if 'ucs_title_from_llm' not in st.session_state:
            st.session_state.ucs_title_from_llm = ""

        if 'section1_triggered' not in st.session_state:
            st.session_state.section1_triggered = False

        st.session_state.app_source_code = st.text_area(
            "Test Case in Application Source Code",
            value="",
            on_change=None,
            height=350,
            placeholder="Test Case in Application Source Code here",
        )
        
        section1_button = st.form_submit_button("Section 1")

        if section1_button:
            # Trigger the second section
            st.session_state.show_section_1 = True
            st.session_state.section1_triggered = True

    # This will only show the second section if 'show_section_2' is set in session_state.
    if st.session_state.get('show_section_1', False):
        first_section()

def first_section():
    if st.session_state.app_source_code and st.session_state.section1_triggered:
        with st.spinner("Getting LLM generated Use Case Scenario"):
            use_case_scenario_examples = 'Example 1:\nGiven the store has "UPS" shipping method with "$20.00" fee\nAnd I have product "The Sorting Hat" in the cart\nWhen I specified the shipping address as "Ankh Morpork", "Frost Alley", "90210", "United States" for "Jon Snow"\nThen I should be on the checkout shipping step\nAnd I should see shipping method "UPS" with fee "$20.00"\n'
            use_case_scenario_examples += 'Example 2:\nGiven the promotion gives free shipping to every order over "$70.00"\nWhen I add product "PHP Mug" to the cart\nAnd I change "PHP Mug" quantity to 4\nThen my cart total should be "$80.00"\nAnd my cart shipping total should be "$0.00"\n'
            st.session_state.ucs_from_llm, llm_contents = application_test_case_to_ucs(st.session_state.app_source_code, use_case_scenario_examples)
            st.session_state.ucs_title_from_llm, llm_contents = ucs_to_ucs_title(llm_contents)
            st.session_state.section1_triggered = False
    
    with st.form(key='first_section'):
        section2_button = st.form_submit_button("Section 2")
        if section2_button:
            # Trigger the second section
            st.session_state.show_section_2 = True

    if st.session_state.get('show_section_2', False):
        second_section()

def second_section():
    with st.form(key='second_section'):
        st.subheader("Step 2: Review Use Case Scenario")

        st.session_state.ucstitle = st.text_input(
            "Title",
            value="" if not st.session_state.ucs_title_from_llm else st.session_state.ucs_title_from_llm,
            on_change=None,
            placeholder="Use Case Scenario Title here",
        )
        manual_ucs = st.text_area(
            "Use Case Scenario",
            value="" if not st.session_state.ucs_from_llm else st.session_state.ucs_from_llm,
            height=350,
            help="use Gherkin language syntax",
            on_change=None,
            placeholder="Use Case Scenario here",
        )

        if st.session_state.ucs_from_llm == "":
            st.session_state.ucs = st.session_state.ucs_from_llm
        else:
            st.session_state.ucs = manual_ucs

        section5_button = st.form_submit_button("Section 5")
        if section5_button:
            st.session_state.show_section_5 = True

    if st.session_state.get('show_section_5', False):
        fifth_section()

def fifth_section():
    st.session_state.capec_related_attacks = set()

    if st.session_state.ucs != "" and st.session_state.ucstitle != "":
        st.session_state.new_ucs = "".join([sentence.strip() + " " for sentence in st.session_state.ucs.split("\n")])
        st.session_state.ents, st.session_state.ent_html = visualize_pos(st.session_state.new_ucs)
        
        st.session_state.capec_attack_patterns = ""
        capec_attack_patterns_temp_list = seperate_capec()

        capec_attack_patterns_set = set()
        for capec_attack_patterns_temp in capec_attack_patterns_temp_list:
            capec_related_attacks = find_capec_related_attacks_llm(st.session_state.ucs, st.session_state.ucstitle, capec_attack_patterns_temp)
            print(capec_related_attacks)
            capec_attack_patterns_set.update(capec_related_attacks)
            time.sleep(30)

        capec_attack_patterns_temp = ""
        for related_attack in capec_related_attacks:
            capec_id = dict(related_attack)["capec_id"].strip()
            title = st.session_state.CAPEC[capec_id]["type"]
            description = st.session_state.CAPEC[capec_id]["description"]
            capec_attack_patterns_temp += f"CAPEC id: {capec_id}: CAPEC Title: {title}. CAPEC description: {description}\n"

        st.session_state.capec_related_attacks = find_capec_related_attacks_llm(st.session_state.ucs, st.session_state.ucstitle, capec_attack_patterns_temp)

        st.subheader("CAPEC Related Attacks")
        if st.session_state.capec_related_attacks:
            for capec_related_attack in st.session_state.capec_related_attacks:
                related_capec_id = dict(capec_related_attack)["capec_id"]
                related_capec_explain = dict(capec_related_attack)['explanation']
                related_capec_confidence = dict(capec_related_attack)['confidence']
                
                if st.session_state.CAPEC.get(related_capec_id) is None:
                    continue
                
                CAPEC_ID = st.session_state.CAPEC[related_capec_id]["capec_id"]
                CAPEC_TITLE = st.session_state.CAPEC[related_capec_id]["type"]
                CAPEC_DESCRIPTION = st.session_state.CAPEC[related_capec_id]["description"]
                st.write(f"ID: {CAPEC_ID}")
                st.write(f"Title: {CAPEC_TITLE}")
                st.write(f"Description: {CAPEC_DESCRIPTION}")
                st.write(f"Explanation: {related_capec_explain}")
                st.write(f"Confidence Score: {related_capec_confidence}")
                st.write("")
        else:
            st.write("There are no CAPEC Related Attacks found.")

        st.header("3. Construct Misuse Case Scenario")

        st.session_state.CWEs_matched, st.session_state.ASVSs_matched = find_weaknesses_and_countermeasures(
            st.session_state.capec_related_attacks
        )
        st.subheader("CWE")
        if st.session_state.CWEs_matched:
            for CWE_matched in st.session_state.CWEs_matched:
                CWE_id = st.session_state.CWE[CWE_matched]["cwe_id"]
                CWE_type = st.session_state.CWE[CWE_matched]["type"]
                CWE_description = st.session_state.CWE[CWE_matched]["description"]
                st.write(f"ID: {CWE_id}")
                st.write(f"Type: {CWE_type}")
                st.write(f"Description: {CWE_description}\n")
                st.write("")
        else:
            st.write("CWE not found")

        st.subheader("ASVS Countermeasures")
        if st.session_state.ASVSs_matched:
            for ASVS_matched in st.session_state.ASVSs_matched:
                ASVS_id = st.session_state.ASVS[ASVS_matched]["asvs_id"]
                ASVS_type = st.session_state.ASVS[ASVS_matched]["type"]
                ASVS_description = st.session_state.ASVS[ASVS_matched]["description"]
                st.write(f"ID: {ASVS_id}")
                st.write(f"Type: {ASVS_type}")
                st.write(f"Description: {ASVS_description}\n")
                st.write("")
        else:
            st.write("ASVS Countermeasures not found")

        st.subheader("Suggested Prompt Design")
        CAPEC_prompt = ""
        for capec_related_attack in st.session_state.capec_related_attacks:
            capec_id = dict(capec_related_attack)['capec_id']
            CAPEC_type = st.session_state.CAPEC[capec_id]["type"]
            CAPEC_description = st.session_state.CAPEC[capec_id]["description"]
            CAPEC_prompt += f"{capec_id}: {CAPEC_type}. {CAPEC_description}\n"

        CWE_prompt = ""
        for CWE_matched in st.session_state.CWEs_matched:
            CWE_id = st.session_state.CWE[CWE_matched]["cwe_id"]
            CWE_type = st.session_state.CWE[CWE_matched]["type"]
            CWE_description = st.session_state.CWE[CWE_matched]["description"]
            CWE_prompt += f"{CWE_id}: {CWE_type}. {CWE_description}\n"

        ASVS_prompt = ""
        for ASVS_matched in st.session_state.ASVSs_matched:
            ASVS_id = st.session_state.ASVS[ASVS_matched]["asvs_id"]
            ASVS_type = st.session_state.ASVS[ASVS_matched]["type"]
            ASVS_description = st.session_state.ASVS[ASVS_matched]["description"]
            ASVS_prompt += f"{ASVS_id}: {ASVS_type}. {ASVS_description}\n"

        Examples_Misuse_Case_Scenario = ""
        for index in range(len(st.session_state.MCS)):
            Examples_Misuse_Case_Scenario += f"Misuse Case Scenario #{index+1}: "+st.session_state.MCS[index]+"\n"

        st.session_state.system, st.session_state.user, st.session_state.prompt = gen_prompt_no_oran(
            st.session_state.ucs,
            st.session_state.ucstitle,
            CAPEC_prompt,
            CWE_prompt,
            ASVS_prompt,
            Examples_Misuse_Case_Scenario,
        )

        st.text_area(label="prompt_design", height=850, value=st.session_state.prompt, disabled=True)

        st.session_state.option = st.selectbox(
            'Which Generative AI LLM Model?',
            ('gpt-3.5-turbo-16k', 'gpt-4')
        )

        if st.session_state.system and st.session_state.user and st.session_state.prompt and st.session_state.option:
            with st.spinner("Getting LLM generated Misuse Case Scenarios"):
                completion = openai.ChatCompletion.create(
                    model=st.session_state.option,
                    messages=[
                        {"role": "system", "content": st.session_state.system},
                        {"role": "user", "content": st.session_state.user}
                    ],
                    temperature=0
                )

                gen_llm_contents = json.loads(completion.choices[0].message["content"])
                for llm_content_index in range(len(gen_llm_contents)):
                    st.text_area(label=f"llm_completion_{llm_content_index+1}", height=150, value=gen_llm_contents[llm_content_index]["misuse_case_scenario"], disabled=True)

def main():
    read_data()
    cs_sidebar()
    start_section()

if __name__ == "__main__":
    main()

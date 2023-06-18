# O-RAN-Near-RT-RIC-Misuse-Case-Scenario-Generator

## Setup
- `pip install --user pipenv`
- `pipenv install streamlit`
  - If error, `pip3 uninstall virtualenv`
- `pipenv install spacy`
- `pipenv install ntlk`
- `pipenv install IPython`

## Run
- `pipenv shell`
- `streamlit run app.py`

## Tests
### Example Use Case Scenario
```
Given a dialer xApp and a listener xApp
And dialer xApp connected to RMR succesfully
And listener xApp connected to RMR succesfully
When dialer xApp sends a message to the listener xApp via RMR
Then the listener xApp receive the message
```

## Prompt design to generate tags for capec.json
### LLM
GPT 3.5
### Prompt Design
```
You are a software developer. You are familiar with CAPEC and want to use CAPEC to match with potential threats. 

Here is the CAPEC title,
<input CAPEC id>: <input CAPEC title>

Here is the CAPEC description,
<input CAPEC description>

Here are the mitigations of CAPEC,
<input mitigations>

Provide me with a list of tags (with respective relevant synonyms). Format as an array of strings for search purposes in my program.
```

## Prompt design to generate tags for oran-components.json and oran-near-rt-ric.json
### LLM
GPT 3.5
### Prompt Design
```
You are a software developer. You are familiar with O-RAN Alliance Security Work Group. Also, you are familiar with the O-RAN Security Threat Modeling and Remediation Analysis document. You want to use the O-RAN Security Threat Modeling and Remediation Analysis document to match with potential threats. 

Here is the O-RAN Security Threat Modeling and Remediation Analysis threat title,
<input threat title>

Here is the O-RAN Security Threat Modeling and Remediation Analysis threat description,
<input threat description>

Provide me with a list of tags (with respective relevant synonyms). Format as an array of strings for search purposes in my program.
```

## Prompt design to generate tags for oran-security-analysis.json
### LLM
GPT 3.5
### Prompt Design
```
You are a software developer. You are familiar with O-RAN Alliance Security Work Group. Also, you are familiar with the Study on Security for Near Real Time RIC and xApps. You want to use the Study on Security for Near Real Time RIC and xApps document to match with potential threats. 

Here is the issue title,
<input issue title>

Here is the issue detail,
<input issue detail>

Here are the security threats as an array of strings,
<input security threats as an array of strings>

Here are the security requirements as an array of strings,
<input security requirements as an array of strings>

Provide me with a list of tags (with respective relevant synonyms). Format as an array of strings for search purposes in my program.
```
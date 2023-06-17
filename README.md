# O-RAN-Near-RT-RIC-Misuse-Case-Scenario-Generator

## Setup
- `pip install --user pipenv`
- `pipenv install streamlit`
  - If error, `pip3 uninstall virtualenv`
- `pipenv install spacy`
- `pipenv install ntlk`
- `pipenv install IPython`

## Run
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
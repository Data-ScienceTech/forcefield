"""LangChain agent protected by ForceField.

Run:
    pip install forcefield[ml] langchain-openai
    export OPENAI_API_KEY=sk-...
    python app.py

Prompts are scanned before LLM calls. Outputs are moderated after generation.
Injection attempts raise PromptBlockedError.
"""

import os
from langchain_openai import ChatOpenAI
from forcefield.integrations.langchain import ForceFieldCallbackHandler

handler = ForceFieldCallbackHandler(sensitivity="high")

llm = ChatOpenAI(
    model="gpt-4",
    api_key=os.environ.get("OPENAI_API_KEY", "sk-test"),
    callbacks=[handler],
)

print("ForceField-protected LangChain agent. Type 'quit' to exit.\n")

while True:
    user_input = input("You: ").strip()
    if user_input.lower() in ("quit", "exit", "q"):
        break

    try:
        response = llm.invoke(user_input)
        print(f"Bot: {response.content}\n")
    except Exception as e:
        print(f"[BLOCKED] {e}\n")

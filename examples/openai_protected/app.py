"""OpenAI chatbot protected by ForceField.

Run:
    pip install forcefield[ml] openai
    export OPENAI_API_KEY=sk-...
    python app.py

All prompts are scanned before reaching the LLM.
Injection attempts are blocked with a PromptBlockedError.
"""

import os
from forcefield.integrations.openai import ForceFieldOpenAI

client = ForceFieldOpenAI(
    openai_api_key=os.environ.get("OPENAI_API_KEY", "sk-test"),
    sensitivity="high",
)

print("ForceField-protected chatbot. Type 'quit' to exit.\n")

while True:
    user_input = input("You: ").strip()
    if user_input.lower() in ("quit", "exit", "q"):
        break

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": user_input},
            ],
            max_tokens=256,
        )
        print(f"Bot: {response.choices[0].message.content}\n")
    except Exception as e:
        print(f"[BLOCKED] {e}\n")

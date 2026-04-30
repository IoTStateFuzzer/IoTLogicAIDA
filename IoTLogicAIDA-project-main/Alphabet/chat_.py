
def get_LLM_response(user_content, system_content, LLM_model):
    client = OpenAI(
        api_key=LLM_CONFIG[LLM_model]["api_key"],
        base_url=LLM_CONFIG[LLM_model]["base_url"]
    )
    response = client.chat.completions.create(
        model=LLM_CONFIG[LLM_model]['select_model'],
        messages=[
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content}
        ],
        stream=False,
        temperature=0.2
    )
    print(f"Receive LLM response, id: {response.id}")
    print(response.choices[0].message.content)
    print("**"*80)
    return response.choices[0].message.content
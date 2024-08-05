
import json

# from agent_app.api.commit import extract_useful_commit_content_info
# from agent_app.inference import prepare_commit_prompt
#
#
# def show_commit_prompt():
#     p = "/root/projects/py_commit/5.log"
#
#     with open(p, 'r') as f:
#         c = f.read()
#
#     l = extract_useful_commit_content_info(c)
#     print(json.dumps(l, indent=4))
#
#     print(prepare_commit_prompt(c)[0])


def ask_gpt():
    from openai import OpenAI

    api_base = ""
    api_key = ""
    client = OpenAI(api_key=api_key, base_url=api_base)

    completion = client.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello!"}
        ]
    )

    print(completion.choices[0].message)


if __name__ == "__main__":
    ask_gpt()

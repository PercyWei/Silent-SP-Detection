import json

from preprocess.log import cprint


msg_thread_file = "/root/projects/VDTest/output/agent/vul_2024-10-08T19:35:54/3-nvdvul_2024-10-08T19:43:39/process_1/loop_1_conversations.json"
with open(msg_thread_file, 'r') as f:
    msgs = json.load(f)

for msg in msgs:
    role = msg["role"]
    content = msg["content"]
    print("=" * 100)
    cprint(f"\n{role.upper()}\n", style='green bold')
    print(f"{content}")
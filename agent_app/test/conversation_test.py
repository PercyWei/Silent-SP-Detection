import json

from preprocess.log import cprint


msg_thread_file = "/root/projects/VDTest/output/agent/py_vul_nvdvul_view1000_results_v1/240-nvdvul_2024-09-22T07:29:39/process_1/loop_1_conversations.json"
with open(msg_thread_file, 'r') as f:
    msgs = json.load(f)

for msg in msgs:
    role = msg["role"]
    content = msg["content"]
    print("=" * 100)
    cprint(f"\n{role.upper()}\n", style='green bold')
    print(f"{content}")
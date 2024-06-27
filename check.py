import pandas as pd
import json
import os

# VulFuncCsv = pd.read_csv('./MSR_data_cleaned.csv')
#
# print(VulFuncCsv.columns)

# for i in range(0, len(VulFuncCsv)):
#     if VulFuncCsv.at[0, 'vul'] == 1:
#         print(VulFuncCsv.at[i, 'func_before'].to_string())
#         print(VulFuncCsv.at[i, 'func_after'].to_string())
#         print(VulFuncCsv.at[i, 'vul_func_with_fix'].to_string())
#         break

# with open('./ReGVD/dataset/function.json', 'r') as f:
#     VulFuncJson = json.load(f)
#
# with open('./ReGVD/dataset/train.jsonl', "r") as file:
#     for line in file:
#         json_obj = json.loads(line)
#         if json_obj['target'] == 1:
#             print(json_obj['func'])
#             break

func_dirpath = './ReGVD/AllFunc'
if not os.path.exists(func_dirpath):
    os.makedirs(func_dirpath)

with open('dataset/ReGVD/dataset/function.json') as ff:
    func_all = json.load(ff)

for idx, func in enumerate(func_all):
        dir_name = f'{idx}'
        fname = f'target_{func["target"]}.c'
        dir = os.path.join(func_dirpath, dir_name)
        os.makedirs(dir, exist_ok=True)
        with open(os.path.join(dir, fname), 'w') as f:
            f.write(func['func'])

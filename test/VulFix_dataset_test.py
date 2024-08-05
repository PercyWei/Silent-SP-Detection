
import csv
import pandas as pd

from typing import *
from loguru import logger


def main(dataset_fpath: str):
    df_header = pd.read_csv(dataset_fpath, nrows=1)
    headers = df_header.columns.tolist()
    logger.info(f'headers: {headers}')

    py_vul_num = 0
    chunk_size = 10000
    for chunk in pd.read_csv(dataset_fpath, chunksize=chunk_size):
        for row in chunk.itertuples(index=False, name="Row"):
            if row.PL == 'python':
                logger.info("|" * 100)
                logger.info(f"Repo: {row.repo}")
                logger.info(f"Commit id: {row.commit_id}")
                logger.info(f"Label: {row.label}")
                if row.label == 1:
                    py_vul_num += 1
                if py_vul_num == 10:
                    return


class A:
    s_a = [1, 2, 3]
    f_a = [4, 5, 6]

    def get_s(self, pref: str):
        l = getattr(self, pref+'_a')[0]
        print(l)


if __name__ == '__main__':
    # logger.remove()
    # logger.add(
    #     'info.log',
    #     mode='w',
    #     level='DEBUG',
    #     format=(
    #         "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level>"
    #         " | <level>{message}</level>"
    #     )
    # )
    # VulFix_dataset_fpath = "/root/projects/VDTest/dataset/VulFix/ase_dataset_sept_19_2021.csv"
    # main(VulFix_dataset_fpath)

    a = A()
    a.get_s('f')

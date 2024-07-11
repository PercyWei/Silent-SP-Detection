import argparse
import json
from typing import *

from old_utils.logging import start_with_logger


def combine_minor_view(
        main_id: int, backbone_id: int, minor_id: int,
        main: Dict, backbone: Dict, minor: Dict):
    logger.info(f"Main VIEW-ID: {main_id}, Backbone VIEW-ID : {backbone_id}, Combined VIEW-ID: {minor_id}.")

    num = 0
    pending_cwe_id_list = []

    for cwe_id, cwe_item in main.items():
        main_attr = f"VIEW-{main_id}"
        assert main_attr in cwe_item

        if len(cwe_item[main_attr]["father"]) != 0:
            num += 1
            logger.info(f"[{num}] Search view attributes of CWE-{cwe_id}")

            minor_attrs = []
            if cwe_id not in minor:

                backbone_father_id_list = backbone[cwe_id][f"VIEW-{backbone_id}"]["father"]
                backbone_child_id_list = backbone[cwe_id][f"VIEW-{backbone_id}"]["children"]

                forward_flag = True
                backward_flag = False
                # Search attributes that all children have
                for child_id in backbone_child_id_list:
                    if child_id not in minor:
                        forward_flag = False
                        break

                # If father has an attribute, child will also have it
                for father_id in backbone_father_id_list:
                    if father_id in minor:
                        backward_flag = True
                        break

                # Search fathers
                if backward_flag:
                    for father_id in backbone_father_id_list:
                        if father_id in minor:
                            minor_attrs = list(set(minor_attrs + minor[father_id][f"VIEW-{minor_id}"]["father"]))

                    if len(minor_attrs) != 0:
                        logger.info(f"[Result] Find VIEW-{minor_id} attributes: {minor_attrs}.")
                        logger.warning(f"[Result] Resources: Fathers in VIEW-{backbone_id}.")

                # Search children
                if forward_flag and len(minor_attrs) == 0:
                    for child_id in backbone_child_id_list:
                        if minor[child_id][f"VIEW-{minor_id}"]["father"] not in minor_attrs:
                            minor_attrs.append(minor[child_id][f"VIEW-{minor_id}"]["father"])

                    if len(minor_attrs) != 0:
                        logger.info(f"[Result] Find VIEW-{minor_id} attributes: {minor_attrs}.")
                        logger.warning(f"[Result] Resources: Children in VIEW-{backbone_id}.")

                if len(minor_attrs) == 0:
                    logger.warning(f"[Result] Can not find VIEW-{minor_id} attributes.")

            else:
                minor_attrs = minor[cwe_id][f"VIEW-{minor_id}"]["father"]

                if len(minor_attrs) == 0:
                    logger.error(f"[Result] As a requirement, CWE-{cwe_id} must not be used to map to real-world vulnerabilities,"
                                 f" but it is violated here.")
                    pending_cwe_id_list.append(cwe_id)
                else:
                    logger.info(f"[Result] Find VIEW-{minor_id} attributes: {minor_attrs}.")
                    logger.info(f"[Result] Resources: Self.")

            if "Attributes" in main[cwe_id]:
                main[cwe_id]["Attributes"][f"VIEW-{minor_id}"] = minor_attrs
            else:
                main[cwe_id]["Attributes"] = {f"VIEW-{minor_id}": minor_attrs}


if __name__ == '__main__':
    logger = start_with_logger(__file__)

    parser = argparse.ArgumentParser(description='Combine different views of CWE tree. '
                                                 'Only consider CWE items in `mainViewJpath`, '
                                                 'and combine them with different views of `minorViewJpath`')
    parser.add_argument('-mid', '--mainViewId',
                        type=int, required=True, help='Main view id (1003).')
    parser.add_argument('-nid', '--minorViewId',
                        type=int, nargs='+', required=True, help='Minor view id (699).')
    parser.add_argument('-bid', '--backboneViewId',
                        type=int, required=True, help='Backbone view id (1000).')
    parser.add_argument('-m', '--mainViewJpath',
                        type=str, required=True, help='Json file path of main view of CWE tree.')
    parser.add_argument('-n', '--minorViewJpath',
                        type=str, nargs='+', required=True, help='Json file path of minor view of CWE tree.')
    parser.add_argument('-b', '--backboneViewJpath',
                        type=str, required=True, help='Json file path of backbone view of CWE tree.')
    parser.add_argument('-s', '--saveJpath',
                        default='./data/completeCWTETree.json', help='Json file path for saving combined CWE tree.')

    args = parser.parse_args()

    main_view_id = args.mainViewId
    minor_view_id_list = args.minorViewId
    backbone_view_id = args.backboneViewId
    main_view_jpath = args.mainViewJpath
    minor_view_jpath_list = args.minorViewJpath
    backbone_view_jpath = args.backboneViewJpath

    assert f'VIEW-{main_view_id}' in main_view_jpath and f'VIEW-{backbone_view_id}' in backbone_view_jpath
    assert len(minor_view_id_list) == len(minor_view_jpath_list)

    with open(main_view_jpath, 'r') as f:
        main_view = json.load(f)

    with open(backbone_view_jpath, 'r') as f:
        backbone_view = json.load(f)

    for minor_view_id, minor_view_jpath in zip(minor_view_id_list, minor_view_jpath_list):
        assert f'VIEW-{minor_view_id}' in minor_view_jpath

        with open(minor_view_jpath, 'r') as f:
            minor_view = json.load(f)

        combine_minor_view(
            main_view_id, backbone_view_id, minor_view_id,
            main_view, backbone_view, minor_view)

    with open(args.saveJpath, 'w') as f:
        json.dump(main_view, f, indent=4)

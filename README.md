# Extract AST, CFG from (single) C/C++/Java file
* Step 1 
  * Use Joern parse source code
  * `python joern_parse.py -s <source_dir> -o <cpgJson_dirpath>`
* Step 2 
  * Extract the desired information from json file
  * `python readCpjJson.py -i <cpgJson_dirpath> -o <rcpg_dirpath>`
* Step 3 
  * Reconstruct AST from rcpg
  * `python getAST.py -i <rcpg_dirpath> -o <ast_dirpath>`

# Dataset cleaning
## TreeVul
### Basic information
* Dataset location: 
  * `./dataset/TreeVul/dataset_cleaned.json` [**dst1**]
  * `./dataset/TreeVul/TreeVul-original.json` [**dst2**]
### Pre-process results
#### 1. Select dataset items with valid commit
* **Step 1**
  * Executable file: `./tools/dataset/clean.py`
  * Method: `check_commits_validity_by_fetching(logger, dataset_jpath, save_dpath)`
  * Params:
    * `dataset_jpath`: **@dst2**
    * `save_dpath`: `./data`(default)
  * Result:
    * Description: <br> 
        A dict containing all check results of the items from original TreeVul dataset. <br>
        There are three forms of check result: _Valid_, _Invalid_ and _Failed_ 
    * Inter result path: `./data/TreeVul-valid_check.json` [**dst3**]
* **Step 2**
  * Executable file: `./tools/dataset/clean.py`
  * Method: `check_failed_commits_by_cloning(logger, check_result_jpath, repo_exists)`
  * Params:
    * `check_result_jpath`: **@dst3**
    * `repo_exists`: `False`
  * Result:
    * Description: <br> 
        Perform further checks on the items that failed in **Step 1**, and save check results in the same loc. 
    * Inter result path: **@dst3**
* **Step 3**
  * Check the repos that failed to clone in **step 2** and manually clone them until all successful.
* **Step 4**
  * Executable file: `./tools/dataset/clean.py`
  * Method: `check_failed_commits_by_cloning(logger, check_result_jpath, repo_exists)`
  * Params:
    * `check_result_jpath`: **@dst3**
    * `repo_exists`: `True` 
  * Result:
    * Description: <br> 
        Perform further checks on the items that failed in **Step 2**, and save check results in the same loc. <br>
        After this step, except for the repos that could not be found, <br> 
        all the dataset items involved in the repos should have been checked successfully.
    * Inter result path: **@dst3**
* **Step 5**
  * Executable file: `./tools/dataset/clean.py`
  * Method: `build_dataset_from_validity_check_results(logger, dataset_jpath, check_result_jpath, save_dpath)`
  * Params:
    * `dataset_jpath`: **@dst2**
    * `check_result_jpath`: **@dst3**
    * `save_dpath`: `./data`(default)
  * Result:
    * Description: <br> 
        Select valid items from original TreeVul dataset to build a new dataset based on the check results.
    * Final result path: `./data/TreeVul-valid.json` [**dst4**]
#### 2. Choose CVEs containing single commit which changes single file
* **Step 1**
  * Executable file: `./tools/dataset/clean.py`
  * Method: `select_cves_with_single_commit(logger, dataset_jpath, save_dpath)`
  * Params:
    * `dataset_jpath`: **@dst4**
    * `save_dpath`: `./data`(default)
  * Result:
    * Description: <br> 
        Select CVEs containing single commit to build a new dataset. <br>
        Note: Each item in dataset **@dst2** (original) or **@dst4** (valid) corresponds to a single file modified in a repo commit.
    * Inter result path: `./data/TreeVul-valid_cve_s_commit.json` [**dst5**]
* **Step 2**
  * Executable file: `./tools/dataset/clean.py`
  * Method: `select_cves_with_single_commit_with_single_file(logger, dataset_jpath, save_dpath)`
  * Params:
    * `dataset_jpath`: **@dst5**
    * `save_dpath`: `./data`(default)
  * Result:
    * Description: <br>
        From CVEs containing single commit to select CVEs containing single commit which changes a single file.
    * Final result path: `./data/TreeVul-valid_cve_s_commit_s_file.json` [**dst6**]

import json
import time
import os
import subprocess

root_path = os.path.dirname(__file__)


def execute_hook(scan_result, action, device_id):
    def execute_command(command):
        if "|hook" not in action:
            process = subprocess.Popen(command, stdout=subprocess.PIPE)
            return process
        subprocess.check_call(command, stdout=subprocess.PIPE)
        return None

    if not os.path.exists(f"{root_path}/{scan_result}/action_script.json"):
        print("No hook script, please check")
        return None

    with open(f"{root_path}/{scan_result}/action_script.json", "r") as file:
        py_file_dict = json.load(file)

    if action not in py_file_dict:
        return None

    # get APP name for attaching
    with open(f"{root_path}/../../analyse_app/ui_scan_result/{scan_result}/valuable_button.json", "r") as button_file:
        app_name = json.load(button_file)["appName"]

    py_scripts_folder_path = f"{root_path}/{scan_result}/py_scripts/"
    command_list = ["python", f"{py_scripts_folder_path}/{py_file_dict[action]}"]

    if "|hook" not in action:
        # hook for knowledge
        command_list.append('-c')
        command_list.append(f'{0 if "local" in action else 1}')
        command_list.append("-d")
        command_list.append(f"{device_id}")
        command_list.append("-a")
        command_list.append(f"{app_name}")
    else:
        # use knowledge file to execute
        knowledge_folder_path = f"{root_path}/{scan_result}/knowledge_files/"
        knowledge_file_list = sorted([x for x in os.listdir(knowledge_folder_path) if action.replace("|hook", "") in x], reverse=True)
        command_list.append("-d")
        command_list.append(f"{device_id}")
        command_list.append("-a")
        command_list.append(f"{app_name}")
        command_list.append('-f')
        command_list.append(knowledge_file_list[-1])

    return execute_command(command_list)


def stop_hook(hook_process):
    try:
        if not hook_process:
            return True
        hook_process.terminate()
        return True
    except Exception as e:
        print(e)
        return False


def clear_knowledge(scan_result_folder):
    try:
        knowledge_folder = f"{root_path}/{scan_result_folder}/knowledge_files/"
        file_list = [x for x in os.listdir(knowledge_folder) if ".json" in x]
        for file in file_list:
            os.remove(f"{knowledge_folder}/{file}")
        return True
    except Exception:
        print("clear knowledge error, maybe no knowledge folder")
        return False


def get_knowledge_list(scan_result, action):
    return [x for x in os.listdir(f"{root_path}/{scan_result}/knowledge_files/") if action.replace("|hook", "") in x]


def has_knowledge(scan_result, action):
    return bool(get_knowledge_list(scan_result, action))

import os

ROOT_FOLDER = os.path.dirname(__file__) + "/../"
JS_FOLDER = ROOT_FOLDER + "js_scripts/"
JSON_FOLDER = ROOT_FOLDER + "knowledge_files/"


def load_script(name, script):
    with open(JS_FOLDER + name,'r') as f:
        # global script
        script += '\n'
        script += f.read()
    return script


def load_script_list(script_list, script):
    for item in script_list:
        script = load_script(item, script)
    return script


def get_true_file_path(file_name):
    if "/" not in file_name:
        if file_name.split('.')[-1] == "js":
            return JS_FOLDER + file_name
        elif file_name.split('.')[-1] == "json":
            return JSON_FOLDER + file_name
    return file_name

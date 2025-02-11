import os
import datetime
import shutil

LOG_FOLDER_ROOT = os.path.dirname(__file__)
# LOG_FILE = LOG_FOLDER_ROOT + "/program.log"
LOG_FILE = f"{LOG_FOLDER_ROOT}/program_{datetime.datetime.now().strftime('%Y%m%d')}.log"

# flag
print_debug_flag = True

# tips
LOG = "[LOG]"
ERROR = "[ERROR]"
DEBUG = "[DEBUG]"


def log_func(log_level: str, log_message: [str, Exception], t_count: int = 0, save_file=True):
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    if log_level == DEBUG and not print_debug_flag:
        pass
    else:
        print(formatted_time, log_level, end=" ")
        for temp_index in range(t_count):
            print("\t", end="")
        print(log_message)

    if save_file:
        with open(LOG_FILE, "a+") as f:
            f.write(formatted_time + " ")
            for temp_index in range(t_count):
                f.write("\t")
            f.write(log_level + " " + str(log_message))
            f.write('\n')


def write_dict_to_file(data: dict, file, log_level=LOG, d_count=0):
    file.write(" {\n")

    for key, value in data.items():
        if isinstance(value, dict):
            for i in range(d_count + 2):
                file.write("\t")
            file.write(f"{key}:")
            write_dict_to_file(value, file, d_count=d_count+1, log_level=log_level)
        elif isinstance(value, list):
            for i in range(d_count + 2):
                file.write("\t")
            file.write(f"{key}:")
            write_list_to_file(value, file, d_count=d_count+1, log_level=log_level)
        else:
            for i in range(d_count + 2):
                file.write("\t")
            file.write(f"{key}: {value}\n")

    for i in range(d_count + 1):
        file.write("\t")
    file.write("}\n")


def write_list_to_file(data: list, file, log_level=LOG, d_count=0):
    file.write(" [\n")

    for item in data:
        if isinstance(item, dict):
            write_dict_to_file(item, file, d_count=d_count+1, log_level=log_level)
        elif isinstance(item, list):
            write_list_to_file(item, file, d_count=d_count+1, log_level=log_level)
        else:
            for i in range(d_count + 2):
                file.write("\t")
            file.write(f"{item}\n")

    for i in range(d_count + 1):
        file.write("\t")
    file.write("]\n")


def log_dict_func(log_level, log_dict: dict, save_file=True):
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    if log_level == DEBUG and not print_debug_flag:
        pass
    else:
        print(formatted_time, log_level, "{")
        for (key, value) in log_dict.items():
            print('\t', key, ": ", value)
        print("}")

    if save_file:
        with open(LOG_FILE, "a+") as f:
            f.write(formatted_time + " " + log_level)
            write_dict_to_file(log_dict, f)


def log_list_func(log_level, log_list: list, save_file=True):
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    if log_level == DEBUG and not print_debug_flag:
        pass
    else:
        print(formatted_time, log_level, "[")
        for item in log_list:
            print('\t', item)
        print("]")

    if save_file:
        with open(LOG_FILE, "a+") as file:
            file.write(formatted_time + " " + log_level)
            write_list_to_file(log_list, file, log_level)


def clear_log():
    print("Clear log...")
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)


def save_log_as_name(log_name_new: str):
    shutil.move(LOG_FILE, LOG_FOLDER_ROOT + "/" + log_name_new)

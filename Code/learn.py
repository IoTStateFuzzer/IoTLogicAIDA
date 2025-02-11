"""
Learn Base model and State fuzzing model
"""
import os
import json
import time
import socket
import subprocess
from tqdm import trange

from Mapper.Operator.device import DeviceCls
from Mapper.Monitor.mitm_network import MitmCLs
from Mapper.Monitor.packet_parser import get_new_op_class_for_response
from Mapper.Operator.HookScripts import mainControl
from Mapper.Mediator.button_constrain import InputSequence
from Logger import mlog
from Scripts.communicate_with_xiaomi_cloud import plug_on, plug_off
from Config import device_appium_config


def my_sleep(sleep_time):
    for index in trange(int(sleep_time/0.1)):
        time.sleep(0.1)


class LearnCls:
    def __init__(self, scan_result_folder):
        # paths
        self.ROOT_PATH = os.path.dirname(__file__)
        self.LEARNLIB_FOLDER = self.ROOT_PATH + "/Learner/"
        self.VALUABLE_BUTTON_FILE = f"{self.ROOT_PATH}/Alphabet/ui_scan_result/{scan_result_folder}/valuable_button.json"

        # reset actions
        self.reset_op_list = None

        # communication information
        self.LOCAL_IP = ""
        self.LOCAL_PORT = 7011
        self.SERVER_IP = "127.0.0.1"
        self.SERVER_PORT = 9999
        self.SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SYSTEM_MESSAGE = 0
        self.LEARNLIB_MESSAGE = 1
        self.QUERY_MESSAGE = 2

    def load_alphabet(self):
        """
        Send a reply to learner to tell the scan results.
        """
        # print log
        mlog.log_func(mlog.LOG, "send input_bat to learner...")

        # load valuable button dictionary
        with open(self.VALUABLE_BUTTON_FILE, "r") as val_but_file:
            but_dict = json.load(val_but_file)

        self.reset_op_list = but_dict["resetActions"]
        overlook_button_list = but_dict["overlookActions"]

        mlog.log_func(mlog.LOG, "reset action list: ")
        mlog.log_list_func(mlog.LOG, self.reset_op_list)

        # load ui_list
        ui_list = []
        for user in but_dict:
            if "user" not in user:
                continue
            for distance in but_dict[user]:
                if distance == "Special":
                    continue
                button_name_list = list(but_dict[user][distance].keys())
                for item in button_name_list:
                    if f"{user}|{distance}|{item}" not in overlook_button_list:
                        ui_list.append(f"{user}|{distance}|{item}")

        mlog.log_list_func(mlog.LOG, ui_list)

        # communicate with the server
        message = self.SOCKET.recv(1024)
        message_type = message[0]
        context = message[1:].decode('utf-8')
        if message_type == self.SYSTEM_MESSAGE and context == "alphabet":
            mlog.log_func(mlog.LOG, "Receive alphabet send request")

            # create file for alphabet
            alphabet_file = self.LEARNLIB_FOLDER + "src/main/resources/input_bat"
            with open(alphabet_file, "w") as f:
                for item in ui_list:
                    if item != ui_list[-1]:
                        f.write(item + "\n")
                    else:
                        f.write(item)
            mlog.log_func(mlog.LOG, "Create the alphabet file input_bat")

            # Send reply message
            reply_context = "Succeed!"
            reply_message = bytes([self.SYSTEM_MESSAGE]) + reply_context.encode('utf-8')
            self.SOCKET.sendall(reply_message)
            mlog.log_func(mlog.LOG, "Send alphabet success")
        else:
            mlog.log_func(mlog.ERROR, "Don't receive alphabet send request")

    def create_socket(self):
        mlog.log_func(mlog.LOG, "Start connecting to server...")
        while True:
            try:
                self.SOCKET.bind((self.LOCAL_IP, self.LOCAL_PORT))
                break
            except OSError as e:
                mlog.log_func(mlog.ERROR, f"{e}, sleep 5s and wait for re-bind")
                my_sleep(5)
        self.SOCKET.connect((self.SERVER_IP, self.SERVER_PORT))
        mlog.log_func(mlog.LOG, "Connection build")

    def close_socket(self):
        mlog.log_func(mlog.LOG, "Close the socket...")
        self.SOCKET.close()

    def response_to_learner(self, output):
        """
        Tell the learner the output of operation.
        :param output: result str from packet parsing
        """
        reply_message = bytes([1]) + output.encode('utf-8')
        mlog.log_func(mlog.LOG, "Send reply message --- <" + output + ">")
        self.SOCKET.sendall(reply_message)

    def get_input_from_learner(self):
        # communicate with the server
        message = self.SOCKET.recv(1024)
        if message:
            message_type = message[0]
            context = message[1:].decode('utf-8')
            print("======================================================================================")
            if message_type == self.SYSTEM_MESSAGE:
                mlog.log_func(mlog.LOG, "Receive system message: " + context)
                return context
            elif message_type == self.LEARNLIB_MESSAGE:
                mlog.log_func(mlog.LOG, "Receive learnlib message: " + context)
                return context
            elif message_type == self.QUERY_MESSAGE:
                mlog.log_func(mlog.LOG, "Receive query message: " + context)
                return context
            else:
                mlog.log_func(mlog.ERROR, "Don't receive input message")

            return context
        else:
            return "closeConnect"


def learn_model_main(scan_result_name, database, learn_dir_name="", select_hookable_actions=[]):
    mlog.log_func(mlog.LOG, "Learn model start")
    if not learn_dir_name:
        learn_dir_name = f"learn_{scan_result_name}"

    # create an entity for learning
    learn_entity = LearnCls(scan_result_name)
    # create sockets to connect to learners for communication
    learn_entity.create_socket()
    # send the alphabet to the learner
    learn_entity.load_alphabet()
    # init flags and turn off the plug
    pro_end_flag = False  # control flag

    plug_off()

    with open(f"{os.path.dirname(__file__)}/../analyse_app/ui_scan_result/{scan_result_name}/valuable_button.json", "r") as valuable_button_file:
        config_button = json.load(valuable_button_file)
        remove_device_sleep_time = config_button["removeDeviceSleepTime"]
        add_device_sleep_time = config_button["addDeviceSleepTime"]
        hookable_action_list = config_button["hookableActions"]

    # init mitm entity
    local_mitm_entity = MitmCLs("local")
    remote_mitm_entity = MitmCLs("remote")
    mitm_entity_list = [
        local_mitm_entity,
        remote_mitm_entity
    ]

    # start mitm
    start_count = 0
    for entity in mitm_entity_list:
        entity.start_mitm_main(not start_count)
        start_count += 1

    # save distance and pcap file name
    distance_capture_dict = {}

    # start tshark for capturing
    for entity in mitm_entity_list:
        capture_file_name = entity.start_tshark(f"{learn_dir_name}")
        # set name
        distance_capture_dict[entity.distance] = capture_file_name

    # set phone config
    phone_entity_dict = device_appium_config.get_user_distance_dict()

    # get connected devices
    device_list = subprocess.check_output("adb devices", shell=True).decode('utf-8').split('\n')[1:-2]
    for device_index in range(len(device_list)):
        device_list[device_index] = device_list[device_index].replace("\tdevice", "")

    # create phone entity for each distance of each user
    for user in phone_entity_dict:
        for distance in phone_entity_dict[user]:
            phone_name = phone_entity_dict[user][distance]
            if device_appium_config.get_phone_did(phone_name) not in device_list:
                mlog.log_func(mlog.ERROR, f"Phone <{phone_name}> not connected")
                phone_entity_dict[user][distance] = None
                continue
            # create entity and init
            phone_entity = DeviceCls(scan_result_name, phone_name, frida_flag=2)
            # start and init
            phone_entity.start_driver_and_init()
            # set pcap file name
            phone_entity.set_packet_name(distance_capture_dict[distance])
            # save handle
            phone_entity_dict[user][distance] = phone_entity

    # check if mitmproxy is start correctly
    for item in mitm_entity_list:
        pro_end_flag = not item.check_sslkey_file_size() and item.check_pcapng_file()
        if pro_end_flag:
            mlog.log_func(mlog.ERROR, f"mitmproxy start error, please check {item.distance}")
            break

    has_device_flag = True

    # start learn
    while not pro_end_flag:
        # Initial cache
        run_cache = InputSequence(scan_result_name, ["Init"])

        # get constrain dictionary
        mlog.log_func(mlog.LOG, "Load button constrain rules")
        mlog.log_dict_func(mlog.LOG, run_cache.constrain_dict)
        mlog.log_dict_func(mlog.LOG, run_cache.conflict_dict)

        # learning
        while True:
            try:
                # get input from learner
                received_action = learn_entity.get_input_from_learner()

                # close connection
                if received_action == "closeConnect":
                    mlog.log_func(mlog.LOG, "Learning program is finish, stop learning...")
                    learn_entity.response_to_learner("close the client")
                    learn_entity.close_socket()
                    pro_end_flag = True
                    break

                # if counterexample occur, check
                if received_action == "checkCounterExample":
                    mlog.log_func(mlog.LOG, "Check the counter example...")
                    learn_entity.response_to_learner("WaitForChecking")
                    continue

                # reset SUL
                if received_action == "Reset":
                    # if not last_run, response directly
                    if not run_cache.has_executed_action_in_current_round():
                        mlog.log_func(mlog.DEBUG, "Send <Reset_suc> by cache")
                        learn_entity.response_to_learner("Reset_suc")
                        continue

                    # clear run cache
                    run_cache.clean()
                    mainControl.clear_knowledge(scan_result_name)

                    # execute reset actions
                    check_reset_list = learn_entity.reset_op_list.copy()
                    for operation_full_name_index in range(len(check_reset_list)):
                        operation_full_name = check_reset_list[operation_full_name_index]
                        mlog.log_func(mlog.LOG, f"Reset action--{operation_full_name}")
                        cur_user = operation_full_name.split("|")[0]
                        cur_distance = operation_full_name.split("|")[1]

                        # if remove device, turn off the plug
                        if "RemoveDevice" in operation_full_name and has_device_flag:
                            plug_on()
                            my_sleep(5)

                        if_click = phone_entity_dict[cur_user][cur_distance].click_button(operation_full_name, show_description_flag=False, user_distance_phone_dict=phone_entity_dict)

                        # if remove device, turn off the plug
                        if "RemoveDevice" in operation_full_name:
                            if if_click:
                                my_sleep(remove_device_sleep_time)
                            has_device_flag = False
                            plug_off()

                    learn_entity.response_to_learner("Reset_suc")
                    my_sleep(1)
                    continue

                cur_user = received_action.split("|")[0]
                cur_distance = received_action.split("|")[1]

                # check if current action is executed by hook
                if ("|hook" in received_action and "user2" in received_action and
                        (not select_hookable_actions or (received_action.replace("|hook", "") in hookable_action_list and received_action.replace("|hook", "") in select_hookable_actions))):
                    time_list = None
                    if run_cache.check_clickable(received_action.replace("|hook", "")):
                        received_action = received_action.replace("|hook", "")
                        hook_process = mainControl.execute_hook(scan_result_name, received_action,
                                                                phone_entity_dict[cur_user][cur_distance].UDID)
                        time_list = phone_entity_dict[cur_user][cur_distance].click_and_save(received_action, phone_entity_dict)
                        mainControl.stop_hook(hook_process)
                    if not time_list:
                        # check knowledge
                        if not mainControl.has_knowledge(scan_result_name, received_action):
                            mlog.log_func(mlog.LOG, "No knowledge file")
                            learn_entity.response_to_learner("NoElement")
                            continue

                        time_list = phone_entity_dict[cur_user][cur_distance].hook_and_save(scan_result_name, received_action)
                else:
                    # if "user1|" in received_action:
                    received_action = received_action.replace("|hook", "")

                    # check if clickable
                    if not run_cache.check_clickable(received_action):
                        mlog.log_func(mlog.LOG, f"Action: {received_action} can't tap --- by cache")
                        run_cache.show()
                        learn_entity.response_to_learner("NoElement")
                        continue

                    # if add device, turn on the plug
                    if "AddDevice" in received_action and not has_device_flag:
                        plug_on()
                        my_sleep(add_device_sleep_time)

                    # hook for getting knowledge if it is user2's action
                    hook_process = None
                    if "user2" in received_action:
                        hook_process = mainControl.execute_hook(scan_result_name, received_action, phone_entity_dict[cur_user][cur_distance].UDID)
                    # click and get start time, end time
                    time_list = phone_entity_dict[cur_user][cur_distance].click_and_save(received_action, phone_entity_dict)
                    # terminal hook progress
                    if "user2" in received_action and hook_process:
                        mainControl.stop_hook(hook_process)

                if isinstance(time_list, list):
                    # update cache
                    run_cache.add(received_action)
                    if "AddDevice" in received_action:
                        has_device_flag = True

                    # turn off the plug
                    if "RemoveDevice" in received_action:
                        my_sleep(remove_device_sleep_time)
                        plug_off()
                        has_device_flag = False

                    # show run cache
                    run_cache.show()

                    # classify
                    time.sleep(0.5)  # wait for writing on disk
                    class_result = get_new_op_class_for_response(database,
                                                                 phone_entity_dict[cur_user][cur_distance].cur_packet_path,
                                                                 mitm_entity_list[0 if "local" in cur_distance else 1].sslkeyfilelog_path,
                                                                 received_action.replace("|hook", ""), time_list[0], time_list[1])

                    if class_result:
                        learn_entity.response_to_learner(class_result)
                    else:
                        mlog.log_func(mlog.ERROR, f"Action <{received_action}> -- No classify result, can not response to learner")
                        pro_end_flag = True
                        break
                elif isinstance(time_list, int) and time_list == -1:
                    mlog.log_func(mlog.ERROR, "WiFi error, exit")
                    pro_end_flag = True
                    break
                else:
                    # can not tap
                    mlog.log_func(mlog.LOG, f"Action: {received_action} can't tap or hook, response <NoElement>")
                    learn_entity.response_to_learner("NoElement")

            except BrokenPipeError:
                mlog.log_func(mlog.ERROR, "Server has broken, quit")
                pro_end_flag = True
                break

        run_cache.clean()
        mainControl.clear_knowledge(scan_result_name)

        # stop mitm and tshark
        for mitm in mitm_entity_list:
            mitm.stop_mitm_and_clear_iptables(f"{mitm.cur_packet_folder}/{mitm.cur_packet_name.split('.')[0]}.txt")
            mitm.stop_tshark()

        # stop frida hook, driver, appium server
        for distance_phone_dict in phone_entity_dict.values():
            for phone in distance_phone_dict.values():
                if phone:
                    phone.stop_driver_and_appium_server()

        if not pro_end_flag:
            mlog.log_func(mlog.ERROR, "Something wrong, restart learning")
            learn_entity.response_to_learner("RestartLearning")

    plug_off()
    learn_entity.close_socket()
    mlog.log_func(mlog.LOG, "Learn finish")


def create_database_manually(scan_result_name, database_name="", test_round=5, reset_at_each_round=False):
    if not database_name:
        database_name = f"{scan_result_name}_database"
    mlog.log_func(mlog.LOG, f"Start creating database of <{database_name}>")
    if not scan_result_name or not os.path.exists(f"{os.path.dirname(__file__)}/../analyse_app/ui_scan_result/{scan_result_name}/valuable_button.json"):
        mlog.log_func(mlog.ERROR, "Parameter 'scan_result_name' error, please check")
        return -2

    # init mitm entity
    local_mitm_entity = MitmCLs("local")
    remote_mitm_entity = MitmCLs("remote")
    mitm_entity_list = [
        local_mitm_entity,
        remote_mitm_entity
    ]

    # start mitm
    start_count = 0
    for entity in mitm_entity_list:
        entity.start_mitm_main(not start_count)
        start_count += 1

    # save distance and pcap file name
    distance_capture_dict = {}

    database_name_with_time = None
    # start tshark -- capture
    for entity in mitm_entity_list:
        capture_file_name = entity.start_tshark(f"{database_name}")
        # set name
        distance_capture_dict[entity.distance] = capture_file_name
        if not database_name_with_time:
            database_name_with_time = "_".join(capture_file_name.split("_")[:-1])

    my_sleep(2)

    error_flag = False
    plug_off()

    # set phone config
    phone_entity_dict = device_appium_config.get_user_distance_dict()

    # get connected devices
    device_list = subprocess.check_output("adb devices", shell=True).decode('utf-8').split('\n')[1:-2]
    for device_index in range(len(device_list)):
        device_list[device_index] = device_list[device_index].replace("\tdevice", "")

    # create phone entity for each distance of each user
    for user in phone_entity_dict:
        for distance in phone_entity_dict[user]:
            phone_name = phone_entity_dict[user][distance]
            if device_appium_config.get_phone_did(phone_name) not in device_list:
                mlog.log_func(mlog.ERROR, f"Phone <{phone_name}> not connected")
                phone_entity_dict[user][distance] = None
                continue
            # create entity and init
            phone_entity = DeviceCls(scan_result_name, phone_name, frida_flag=2)
            # start and init
            phone_entity.start_driver_and_init()
            # set pcap file name
            phone_entity.set_packet_name(distance_capture_dict[distance])
            # save handle
            phone_entity_dict[user][distance] = phone_entity

    # check if correct
    for item in mitm_entity_list:
        error_flag = not item.check_sslkey_file_size() and item.check_pcapng_file()
        if error_flag:
            mlog.log_func(mlog.ERROR, f"mitmproxy start error, please check {item.distance}")

    if not error_flag:
        # load valuable button dictionary
        with open(f"{os.path.dirname(__file__)}/../analyse_app/ui_scan_result/{scan_result_name}/valuable_button.json", "r") as val_but_file:
            temp_read_result = json.load(val_but_file)
            reset_op_list = temp_read_result["resetActions"]
            test_action_list = temp_read_result["createDatabaseActionOrder"]
            add_device_sleep_time = int(temp_read_result["addDeviceSleepTime"])
            remove_device_sleep_time = int(temp_read_result["removeDeviceSleepTime"])

        mlog.log_func(mlog.LOG, "Test action list")
        mlog.log_list_func(mlog.LOG, test_action_list)
        mlog.log_func(mlog.LOG, "Reset action list")
        mlog.log_list_func(mlog.LOG, reset_op_list)

        # reset
        if not reset_at_each_round:
            mlog.log_func(mlog.LOG, "Reset")
            for operation_full_name in reset_op_list:
                mlog.log_func(mlog.LOG, f"Reset operation--{operation_full_name}")
                cur_user = operation_full_name.split("|")[0]
                cur_distance = operation_full_name.split("|")[1]

                if "RemoveDevice" in operation_full_name or "UnshareCamera" in operation_full_name:
                    plug_on()
                    my_sleep(3)
                # click and save file
                click_result = phone_entity_dict[cur_user][cur_distance].click_button(operation_full_name, phone_entity_dict)
                # if remove device, turn off the plug
                if "RemoveDevice" in operation_full_name:
                    if click_result:
                        my_sleep(remove_device_sleep_time)
                    plug_off()
            my_sleep(2)

        mlog.log_func(mlog.LOG, "Create database start")
        # start test
        for count in range(test_round):
            if error_flag:
                break

            if reset_at_each_round:
                # reset
                mlog.log_func(mlog.LOG, "Reset")
                for operation_full_name in reset_op_list:
                    mlog.log_func(mlog.LOG, f"Reset operation--{operation_full_name}")
                    cur_user = operation_full_name.split("|")[0]
                    cur_distance = operation_full_name.split("|")[1]

                    # back to home
                    if not phone_entity_dict[cur_user][cur_distance].back_to_home():
                        error_flag = True
                        mlog.log_func(mlog.ERROR, "Can not back to home when reset, please check your device")
                        break

                    if "RemoveDevice" in operation_full_name:
                        plug_on()
                        my_sleep(3)
                    # click and save file
                    phone_entity_dict[cur_user][cur_distance].click_button(operation_full_name, phone_entity_dict)
                    # if remove device, turn off the plug
                    if "RemoveDevice" in operation_full_name:
                        my_sleep(remove_device_sleep_time)
                        plug_off()
                my_sleep(2)

            # click
            for index in range(len(test_action_list)):
                mlog.log_func(mlog.LOG, f"Current test count: {count+1}/{test_round} -- {index+1}/{len(test_action_list)}")
                operation_full_name = test_action_list[index]

                # if add device
                if "AddDevice" in operation_full_name:
                    plug_on()
                    my_sleep(add_device_sleep_time)

                cur_user = operation_full_name.split("|")[0]
                cur_distance = operation_full_name.split("|")[1]

                # click and save file
                while not phone_entity_dict[cur_user][cur_distance].click_and_save(operation_full_name, phone_entity_dict):
                    if not phone_entity_dict[cur_user][cur_distance].back_to_home():
                        phone_entity_dict[cur_user][cur_distance].stop_and_restart_app()

                # if remove device, turn off the plug
                if "RemoveDevice" in operation_full_name:
                    my_sleep(remove_device_sleep_time)
                    plug_off()

                time.sleep(1)
            my_sleep(2)

    # create database finish
    if not error_flag:
        mlog.log_func(mlog.LOG, f"Create database -- {database_name} -- finish")

    # stop mitm and tshark
    for mitm in mitm_entity_list:
        mitm.stop_mitm_and_clear_iptables(f"{mitm.cur_packet_folder}/{mitm.cur_packet_name.split('.')[0]}.txt")
        mitm.stop_tshark()

    # stop frida hook, driver, appium server
    for distance_phone_dict in phone_entity_dict.values():
        for phone in distance_phone_dict.values():
            if phone:
                phone.stop_driver_and_appium_server()

    return database_name_with_time


if __name__ == "__main__":
    # create_database_manually("tuya", test_round=7)
    # learn_model_main("tuya", "tuya_database_1730168155", select_hookable_actions=["user2|remote|DeviceControl"])

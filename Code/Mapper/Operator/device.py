from __future__ import print_function
import os
import json

from appium import webdriver
from selenium.webdriver.common.by import By
from appium.webdriver.common.touch_action import TouchAction
import time
import subprocess
from tqdm import trange

from Mapper.Operator.HookScripts import mainControl
from Logger import mlog
from Config import device_appium_config
from Config import config_file


def my_sleep(sleep_time):
    for index in trange(int(sleep_time/0.1)):
        time.sleep(0.1)


class DeviceCls:
    def __init__(self, scan_folder_name, device_name, frida_flag, restart_app_flag=True):
        """

        :param scan_folder_name:
        :param device_name: phone
        :param frida_flag: 0/False: no frida; 1: -F; 2: -f
        :param restart_app_flag: True: restart app; False: not restart app
        """
        # paths
        self.ROOT_PATH = os.path.dirname(__file__)
        self.LOG_FOLDER_PATH = self.ROOT_PATH + "/../../Logger/"
        self.PACKET_ROOT_PATH = self.ROOT_PATH + "/../Monitor/packets/"
        self.SCRIPTS_FOLDER = self.ROOT_PATH + "/../../Scripts/"
        self.VALUABLE_BUTTON_FILE = f"{self.ROOT_PATH}/../../Alphabet/ui_scan_result/{scan_folder_name}/valuable_button.json"
        self.APPIUM_PATH = config_file.appium_path

        # get config of device
        self.DEVICE_CONFIG_DICT = device_appium_config.get_phone_config_by_name(device_name)
        if not self.DEVICE_CONFIG_DICT:
            mlog.log_func(mlog.ERROR, "Do not have device_name: " + device_name + ". Please check your input.")
            mlog.log_list_func(mlog.ERROR, device_appium_config.get_phone_name_list())
            exit(10)
        self.DEVICE_NAME = device_name
        self.UDID = self.DEVICE_CONFIG_DICT["udid"]
        self.APPIUM_IP = self.DEVICE_CONFIG_DICT["additionalMess"]["appium_ip"]
        self.APPIUM_PORT = self.DEVICE_CONFIG_DICT["additionalMess"]["port"]
        self.DISTANCE = self.DEVICE_CONFIG_DICT["additionalMess"]["distance"]
        self.WIRELESS_CARD = config_file.wireless_card_dict[self.DISTANCE]["card"]
        self.USER = self.DEVICE_CONFIG_DICT["additionalMess"]["user"]
        self.APP_POSITION = self.DEVICE_CONFIG_DICT["additionalMess"]["app_posi"]
        self.DESKTOP_ACTIVITY = self.DEVICE_CONFIG_DICT["additionalMess"]["desktop_activity"]
        self._UNLOCK_PWD = self.DEVICE_CONFIG_DICT["additionalMess"]["unlock_password"] if "unlock_password" in self.DEVICE_CONFIG_DICT["additionalMess"] else ""

        self.APK_NAME = None
        self.APP_ACTIVITY = None
        self.HOME_PAGE_ACTIVITY = None
        self.APP_NAME = None

        # test flag and other info
        self.update_act_flag = False
        self.admin_password = config_file.system_password
        self.cur_packet_name = ""
        self.cur_packet_folder = ""
        self.cur_packet_path = ""

        mlog.log_func(mlog.LOG, f"Current device: <{self.DEVICE_NAME}>, user: <{self.USER}>, distance: <{self.DISTANCE}>")

        # set ip
        self.ip = ""
        self.set_ip()

        # get valuable_button_dict
        self.val_but_dict = self.get_valuable_button()

        self.driver = None
        self.hook_process = None
        self.appium_process = None

        self.frida_flag = int(frida_flag)
        if not self.check_flag_and_start_frida_server():
            exit(2)

        # start app and hook
        self.stop_and_restart_app(restart_app_flag)

        # start appium server
        self._stop_appium_server()
        self._start_appium_server(self.APPIUM_PATH)
        time.sleep(1)

        if self.DISTANCE == "local":
            self.set_iptables_between_phone_and_devices_on_phone()

    def get_valuable_button(self) -> dict:
        with open(self.VALUABLE_BUTTON_FILE, "r") as f:
            valuable_button_click_path = json.load(f)

        if self.USER not in valuable_button_click_path:
            mlog.log_func(mlog.ERROR, f"{self.USER} is not in valuable_buttion.json")
            exit(-2)

        self.APK_NAME = valuable_button_click_path["appPackage"]
        self.APP_ACTIVITY = valuable_button_click_path["appStartActivity"]
        self.HOME_PAGE_ACTIVITY = valuable_button_click_path["homePage"]
        self.APP_NAME = valuable_button_click_path["appName"]

        result = dict()
        result[self.DISTANCE] = valuable_button_click_path[self.USER][self.DISTANCE]
        # result["Special"] = valuable_button_click_path[self.USER]["Special"]
        result["Special"] = valuable_button_click_path["Special"]

        return result

    def _check_frida_server(self):
        try:
            check_command = f"frida-ps -D {self.UDID} | grep {config_file.frida_server_path.split('/')[-1]}"
            frida_pid = subprocess.check_output(check_command, shell=True).decode("utf-8").split()[0]
            return frida_pid
        except subprocess.CalledProcessError:
            return None

    def check_flag_and_start_frida_server(self):
        if not self.frida_flag:
            return True
        elif self.frida_flag == 1 or self.frida_flag == 2:
            self._stop_frida_server()
            self._start_frida_server()
            return self._check_frida_server()
        else:
            mlog.log_func(mlog.ERROR, "frida_flag error: 1--F, 2--f, 0 or False--no frida")
            return False

    def _start_frida_server(self):
        mlog.log_func(mlog.LOG, f"Start frida server on phone <{self.DEVICE_NAME}>, path: {config_file.frida_server_path}")
        start_command = f'adb -s {self.UDID} shell su -c "{config_file.frida_server_path}" &'
        subprocess.run(start_command, shell=True)
        time.sleep(1)

    def _start_frida_hook(self):
        # start disable ssl pinning
        if self.frida_flag:
            command = f"frida -D {self.UDID} -{'F' if self.frida_flag == 1 else 'f'} {self.APK_NAME} -l {self.ROOT_PATH}/pinning_disable.js"
            self.hook_process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, shell=True, preexec_fn=os.setsid)
            time.sleep(3)

    def _stop_frida_hook(self):
        if self.hook_process:
            # mlog.log_func(mlog.DEBUG, "stop hook process by os.killpg")
            os.killpg(os.getpgid(self.hook_process.pid), 15)
            time.sleep(1)
        else:
            try:
                # mlog.log_func(mlog.DEBUG, "stop hook process by kill")
                hook_output = subprocess.check_output(f"ps aux|grep 'frida -D {self.UDID}'", shell=True).decode('utf-8').split('\n')[:-3]
                for line in hook_output:
                    pid = line.split()[1]
                    command = f"kill -15 {pid}"
                    os.system('echo %s | sudo -S %s' % (self.admin_password, command))
            except Exception:
                pass

    def _stop_frida_server(self):
        frida_server_pid = self._check_frida_server()
        if frida_server_pid:
            # mlog.log_func(mlog.LOG, f"Stop frida server on phone <{self.DEVICE_NAME}>")
            self.execute_adb_shell_command(f"kill -9 {frida_server_pid}", root=True)

    def _start_appium_server(self, path_to_appium):
        mlog.log_func(mlog.LOG, "Start appium service....")

        # set appium path
        path = "/".join(path_to_appium.split("/")[:-1]) + ":"
        os.environ['PATH'] = path + os.environ['PATH']

        # start server
        command = f"{path_to_appium} -p {self.APPIUM_PORT} --relaxed-security --session-override"
        self.appium_process = subprocess.Popen(command, stdout=subprocess.DEVNULL, shell=True, preexec_fn=os.setsid)

    def _stop_appium_server(self):
        if self.appium_process:
            mlog.log_func(mlog.DEBUG, "stop appium server by os.killpg")
            os.killpg(os.getpgid(self.appium_process.pid), 9)
        else:
            mlog.log_func(mlog.DEBUG, "stop appium server by kill")
            output = subprocess.check_output(f"ps aux|grep 'appium -p {self.APPIUM_PORT}'", shell=True).decode(
                'utf-8').split('\n')[:-3]
            for line in output:
                pid = line.split()[1]
                command = f"kill -15 {pid}"
                os.system('echo %s | sudo -S %s' % (self.admin_password, command))

    def set_iptables_between_phone_and_devices_on_phone(self):
        def get_userId_of_apk():
            return self.execute_adb_shell_command(f"dumpsys package {self.APK_NAME} |grep userId").split()[-1].split("=")[-1]
        userId_on_phone = get_userId_of_apk()
        device_ip_list = device_appium_config.get_device_ip_list()
        for dev_ip in device_ip_list:
            # command = f"iptables -A OUTPUT -m owner --uid-owner {userId_on_phone} -p udp -j CONNMARK --set-mark 1"
            command = f"iptables -A OUTPUT -m owner --uid-owner {userId_on_phone} -d {dev_ip} -j CONNMARK --set-mark 1"
            self.execute_adb_shell_command(command, root=True)

            # command = "iptables -A INPUT -m connmark --mark 1 -p udp -j NFLOG --nflog-group 30"
            command = f"iptables -A INPUT -m connmark --mark 1 -s {dev_ip} -j NFLOG --nflog-group 30"
            self.execute_adb_shell_command(command, root=True)

            # command = "iptables -A OUTPUT -m connmark --mark 1 -p udp -j NFLOG --nflog-group 30"
            command = f"iptables -A OUTPUT -m connmark --mark 1 -d {dev_ip} -j NFLOG --nflog-group 30"
            self.execute_adb_shell_command(command, root=True)

    def clear_iptables_rules_on_phone(self):
        clear_command = "iptables -F"
        self.execute_adb_shell_command(clear_command, root=True)

    def start_driver(self):
        """
        read config of device and start appium driver
        :return: device driver for auto click
        """
        mlog.log_func(mlog.LOG, "Get device config:")
        device_conf = dict()
        # remove additional message
        for key in self.DEVICE_CONFIG_DICT:
            if key != "additionalMess":
                device_conf[key] = self.DEVICE_CONFIG_DICT[key]
        device_conf["appPackage"] = self.APK_NAME
        device_conf["appActivity"] = self.APP_ACTIVITY
        
        mlog.log_dict_func(mlog.LOG, device_conf)

        driver = webdriver.Remote(self.APPIUM_IP, device_conf)
        self.driver = driver

    def start_driver_and_init(self, back_to_homepage=True):
        self.start_driver()

        if back_to_homepage:
            while not self.back_to_home():
                self.stop_and_restart_app()

    def stop_driver_and_appium_server(self, stop_app_flag=False):
        mlog.log_func(mlog.LOG, f"Driver <{self.DEVICE_NAME}> quit")
        # stop frida
        if self.frida_flag:
            self._stop_frida_hook()
            self._stop_frida_server()

        # stop driver and appium server
        if self.driver:
            self.driver.quit()
        self._stop_appium_server()

        # clear iptables rules on phone
        if self.DISTANCE == "local":
            self.clear_iptables_rules_on_phone()

        # stop app
        if stop_app_flag:
            self.stop_app()

    def stop_and_restart_app(self, stop_flag=True):
        # stop and restart
        if stop_flag:
            self.stop_app()
            self.start_app()
            time.sleep(1)

    def stop_app(self):
        mlog.log_func(mlog.LOG, f"Device <{self.DEVICE_NAME}> stop APP <{self.APK_NAME}>")
        self._stop_frida_hook()
        # back to desktop
        self.press_home_key()
        time.sleep(0.5)
        # stop
        self.execute_adb_shell_command(f"am force-stop {self.APK_NAME}", root=False)
        time.sleep(1)

    def start_app(self):
        if not self.frida_flag:
            # mlog.log_func(mlog.LOG, f"Tap to start APP <{self.APK_NAME}> on device <{self.DEVICE_NAME}>")
            self.execute_adb_shell_command(f"input tap {self.APP_POSITION[0]} {self.APP_POSITION[1]}", root=False)
            # waiting for restart
            if self.DEVICE_NAME != "nexus":
                time.sleep(3)
            else:
                time.sleep(8)

        self._start_frida_hook()

    def back_to_home(self, refresh=True):
        mlog.log_func(mlog.LOG, f"<{self.DEVICE_NAME}> Back to homepage")
        back_count = 0
        while not (self.driver.current_activity == self.HOME_PAGE_ACTIVITY
                   or f"{self.APK_NAME}/{self.driver.current_activity}" == self.HOME_PAGE_ACTIVITY
                   or f"{self.APK_NAME}{self.driver.current_activity}" == self.HOME_PAGE_ACTIVITY):
            self.driver.back()
            time.sleep(0.3)

            back_count += 1
            # something wrong with frida or appium or app
            if back_count > 15:
                mlog.log_func(mlog.ERROR, f"Something wrong with <{self.DEVICE_NAME}>'s appium or app, can not back to home, please [restart app and restart learn]")
                return False

        # if "xiaomi" not in self.APK_NAME and "gongniu" not in self.APK_NAME:
        #     self.driver.back()

        back_count = 0
        while "BackHome" in self.val_but_dict["Special"] and not self.click_button("|BackHome", user_distance_phone_dict=None, show_description_flag=False):
            self.driver.back()
            time.sleep(0.5)

            back_count += 1
            if back_count > 3:
                return False

        if refresh:
            self.pull_to_refresh()
        time.sleep(0.5)
        return True

    def click_and_save(self, ui_name, user_distance_phone_dict, waiting_time=config_file.wait_traffic_time):
        """
        Click the button
        :param ui_name: action name
        :param waiting_time:
        :return: true or false
        """
        ui_name = ui_name.replace("|hook", "")
        mlog.log_func(mlog.LOG, f"Click task-----<{ui_name}>")

        # back home and check
        action = ui_name.split("|")[-1]

        is_special_op = False
        if action in self.val_but_dict["Special"]:
            is_special_op = True
        elif action not in self.val_but_dict[ui_name.split("|")[1]].keys():
            mlog.log_func(mlog.ERROR, f"UI <{ui_name}> which will be clicked is not in config/valuable_button.json")
            return False

        # get click path
        click_path_dict = self.val_but_dict[ui_name.split("|")[1]][action] if not is_special_op else \
        self.val_but_dict["Special"][action]

        # check whether action need to back homepage
        if not ("no_need_back_homepage" in click_path_dict and click_path_dict[
            "no_need_back_homepage"]):
            while not self.back_to_home(refresh=False):
                mlog.log_func(mlog.ERROR, "Could not back to home")
                self.stop_and_restart_app()

        # start tcpdump on phone
        if "local" in ui_name and "Device" in ui_name:
            pcap_on_phone_path = self.start_tcpdump_capture()

        # start click
        start_time = int(time.time())
        # click and return start_time, end_time
        if self.click_button(ui_name, user_distance_phone_dict):
            if is_special_op:
                return [start_time, 1]
            my_sleep(waiting_time)
            end_time = int(time.time())
            # save log
            action_log_folder = self.cur_packet_folder + self.USER + "/" + ui_name.split("|")[-1] + "/"
            action_log_file = f"{action_log_folder}{ui_name}_{start_time}.txt"
            if not os.path.exists(action_log_folder):
                os.makedirs(action_log_folder)

            # write in log
            with open(action_log_file, "w") as log:
                log.write(self.cur_packet_name)
                log.write('\n')
                log.write(str(start_time))
                log.write('\n')
                log.write(str(end_time))

            # pull pcap file
            if "local" in ui_name and "Device" in ui_name:
                self.stop_tcpdump_and_pull_to_local(pcap_path_on_phone=pcap_on_phone_path, save_path=f"{action_log_folder}{ui_name.split('|')[-1]}_{start_time}")

            return [start_time, end_time]

        # no element
        return False

    def click_button(self, ui_name, user_distance_phone_dict, show_description_flag:bool=True, **command_params):
        """

        :param ui_name:
        :param user_distance_phone_dict:
        :param show_description_flag:
        :param command_params:
        :return:
        """
        action = ui_name.split("|")[-1]

        is_special_op = True if action in self.val_but_dict["Special"] else False

        # get click path
        click_path_dict = self.val_but_dict[ui_name.split("|")[1]][action] if not is_special_op else self.val_but_dict["Special"][action]

        # check whether action need to back homepage
        if not ("no_need_back_homepage" in click_path_dict and click_path_dict["no_need_back_homepage"]):
            while not self.back_to_home():
                mlog.log_func(mlog.ERROR, "Could not back to home")
                self.stop_and_restart_app()

        # click one by one
        for index in click_path_dict.keys():
            if index == "no_need_back_homepage":
                continue

            if "restartApp" in click_path_dict[index] and click_path_dict[index]["restartApp"]:
                self.stop_app()
                self.start_app()
                continue

            # waiting
            if "waiting_time" in click_path_dict[index].keys():
                my_sleep(click_path_dict[index]["waiting_time"])

            # refresh before click
            if "refresh" in click_path_dict[index] and click_path_dict[index]["refresh"]:
                self.pull_to_refresh()

            if "bottom" in click_path_dict[index] and click_path_dict[index]["bottom"]:
                time.sleep(0.5)
                self.scroll_to_bottom()
                time.sleep(0.5)

            # print message
            if show_description_flag:
                mlog.log_func(mlog.LOG, index + "---" + click_path_dict[index]["description"], t_count=1) if "description" in click_path_dict[index].keys() else mlog.log_func(mlog.LOG, index + "---" + action + ": " + click_path_dict[index], t_count=1)

            if 'otherPhoneAction' in click_path_dict[index]:
                user_distance_phone_dict[click_path_dict[index]['otherPhoneAction'].split('|')[0]][click_path_dict[index]['otherPhoneAction'].split('|')[1]].click_button(click_path_dict[index]['otherPhoneAction'], user_distance_phone_dict, show_description_flag)
                continue

            if "getScreenShot" in click_path_dict[index] and click_path_dict[index]["getScreenShot"]:
                time.sleep(0.5)
                self.save_screenshot()
                continue

            if "command" in click_path_dict[index]:
                if not click_path_dict[index]["command"]["need_params"]:
                    command = click_path_dict[index]["command"]["command_expression"]
                else:
                    command_split_list = click_path_dict[index]["command"]["command_expression"].split()
                    for command_index in range(len(command_split_list)):
                        if "---" not in command_split_list[command_index]:
                            continue
                        if command_split_list[command_index][3:] not in command_params:
                            mlog.log_func(mlog.ERROR, "Parameter error when executing command in click_button, please check")
                            return False
                        else:
                            command_split_list[command_index] = command_params[command_split_list[command_index][3:]]
                    command = " ".join(command_split_list)
                self.execute_adb_shell_command(command, root=click_path_dict[index]["command"]["root"], is_shell=click_path_dict[index]["command"]["is_shell"])
                continue

            if "posi_x" in click_path_dict[index].keys() and "posi_y" in click_path_dict[index].keys():
                # click by x y
                TouchAction(self.driver).long_press(x=click_path_dict[index]["posi_x"], y=click_path_dict[index]["posi_y"]).perform() if "long_press" in click_path_dict[index] and click_path_dict[index]["long_press"] else self.driver.tap([(click_path_dict[index]["posi_x"], click_path_dict[index]["posi_y"])])
            elif "xpath" in click_path_dict[index] or "resource_id" in click_path_dict[index]:
                # click by xpath or resource id
                is_xpath = "xpath" in click_path_dict[index].keys()
                # get position
                cur_ui_position = click_path_dict[index]["xpath"] if is_xpath else click_path_dict[index]["resource_id"]

                # try to click
                find_flag = False
                try_click_count = 0
                # for click_count in range(3):
                while try_click_count < 3:
                    try:
                        # click
                        target = self.driver.find_element(By.XPATH if is_xpath else By.ID, cur_ui_position)
                        TouchAction(self.driver).long_press(target).perform() if "long_press" in click_path_dict[index] and click_path_dict[index]["long_press"] else target.click()
                        # if input text
                        if "input_text" in click_path_dict[index].keys():
                            input_command = f'input text {click_path_dict[index]["input_text"]}'
                            self.execute_adb_shell_command(input_command, root=False)
                            self.driver.hide_keyboard()
                            time.sleep(0.5)

                        find_flag = True
                        break
                    except Exception:
                        time.sleep(0.5)
                        if "wait_until_exist" in click_path_dict[index] and click_path_dict[index]["wait_until_exist"]:
                            continue
                        else:
                            try_click_count += 1

                if not find_flag:
                    # check if this can not exist
                    if "can_not_exist" in click_path_dict[index] and click_path_dict[index]["can_not_exist"]:
                        if "not_exist_and_do" in click_path_dict[index] and click_path_dict[index]["not_exist_and_do"]:
                            self.click_button(click_path_dict[index]["not_exist_and_do"], user_distance_phone_dict=user_distance_phone_dict)
                        elif "not_exist_and_other_phone_do" in click_path_dict[index] and click_path_dict[index]["not_exist_and_other_phone_do"]:
                            user_distance_phone_dict[click_path_dict[index]['not_exist_and_other_phone_do'].split('|')[0]][
                                click_path_dict[index]['not_exist_and_other_phone_do'].split('|')[1]].click_button(
                                click_path_dict[index]['not_exist_and_other_phone_do'], user_distance_phone_dict,
                                show_description_flag)
                        else:
                            continue
                    else:
                        if show_description_flag:
                            mlog.log_func(mlog.LOG, "Can not find element when --- " + click_path_dict[index]["description"], t_count=2)
                        return False
                else:
                    if "exist_and_do" in click_path_dict[index]:
                        self.click_button(click_path_dict[index]["exist_and_do"], user_distance_phone_dict=user_distance_phone_dict)

            if "back" in click_path_dict[index] and click_path_dict[index]['back']:
                self.driver.back()

            if 'back_to_home' in click_path_dict[index] and click_path_dict[index]['back_to_home']:
                self.back_to_home(refresh=False)

        return True

    def hook_and_save(self, scan_result, ui_name, waiting_time=config_file.wait_traffic_time):
        mlog.log_func(mlog.LOG, f"Hook task-----<{ui_name}>")

        # start tcpdump on phone
        if "local" in ui_name and "Device" in ui_name:
            pcap_on_phone_path = self.start_tcpdump_capture()

        # execute by hook and return start_time, end_time
        start_time = int(time.time())
        hook_process = mainControl.execute_hook(scan_result, ui_name, self.UDID)
        time.sleep(waiting_time)
        mainControl.stop_hook(hook_process)
        end_time = int(time.time())

        # save log
        ui_name = ui_name.replace("|hook", "")
        action_log_folder = f"{self.cur_packet_folder}/{self.USER}/{ui_name.split('|')[-1]}/"
        if not os.path.exists(action_log_folder):
            os.makedirs(action_log_folder)
        with open(f"{action_log_folder}/hook_record.txt", "a+") as hook_record_file:
            hook_record_file.write(f"{ui_name}_{start_time}\n")

        # write in log
        with open(f"{action_log_folder}/{ui_name}_{start_time}.txt", "w") as log:
            log.write(self.cur_packet_name)
            log.write('\n')
            log.write(str(start_time))
            log.write('\n')
            log.write(str(end_time))

        if "local" in ui_name and "Device" in ui_name:
            self.stop_tcpdump_and_pull_to_local(pcap_path_on_phone=pcap_on_phone_path,
                                                save_path=f"{action_log_folder}{ui_name.split('|')[-1]}_{start_time}")

        return [start_time, end_time]

    def pull_to_refresh(self):
        mlog.log_func(mlog.LOG, f"<{self.DEVICE_NAME}> Refresh at homepage")
        # get window size
        window_size = self.driver.get_window_size()
        width = window_size['width']
        height = window_size['height']

        # define start point and end point
        start_x = width / 2
        start_y = height / 8 if "tuya" not in self.APK_NAME else height / 5
        end_x = start_x
        end_y = height * 3 / 5
        swipe_time = 500

        # up to awake
        swipe_command = f"input swipe {start_x} 250 {end_x} 200 {swipe_time}"
        self.execute_adb_shell_command(swipe_command)
        time.sleep(0.3)
        swipe_command = f"input swipe {end_x} 200 {start_x} 250 {swipe_time}"
        self.execute_adb_shell_command(swipe_command)
        time.sleep(0.3)

        # refresh
        swipe_command = f"input swipe {start_x} {start_y} {end_x} {end_y} {swipe_time}"
        self.execute_adb_shell_command(swipe_command)
        # my_sleep(2)

    def scroll_to_bottom(self):
        # get window size
        window_size = self.driver.get_window_size()
        width = window_size['width']
        height = window_size['height']

        # define start point and end point
        # start_x = width / 2
        start_x = 150
        end_y = height / 6
        end_x = start_x
        start_y = height * 3 / 4
        swipe_time = 500

        # up to awake
        swipe_command = f"input swipe {start_x} 250 {end_x} 200 {swipe_time}"
        self.execute_adb_shell_command(swipe_command)
        time.sleep(0.5)

        swipe_command = f"input swipe {start_x} {start_y} {end_x} {end_y} {swipe_time}"
        self.execute_adb_shell_command(swipe_command)

    def set_packet_name(self, pcap_name):
        self.cur_packet_name = pcap_name
        self.cur_packet_folder = self.PACKET_ROOT_PATH + "_".join(self.cur_packet_name.split("_")[:-1]) + "/" + self.cur_packet_name.split("_")[-1][:-7] + "/"
        self.cur_packet_path = self.cur_packet_folder + pcap_name

    def is_desktop(self, desktop_activity):
        return self.driver.current_activity == desktop_activity

    def execute_adb_shell_command(self, shell_command, root=False, is_shell=True):
        try:
            if is_shell:
                adb_command_list = ["adb", "-s", self.UDID, "shell", f'"{shell_command}"'] if not root \
                    else ["adb", "-s", self.UDID, "shell", "su", "-c", f'"{shell_command}"']
            else:
                adb_command_list = ["adb", "-s", self.UDID, shell_command]
            output = subprocess.check_output(" ".join(adb_command_list), shell=True, stderr=subprocess.DEVNULL)
            return output.decode("utf-8")
        except Exception as e:
            mlog.log_func(mlog.ERROR, f"Error executing adb shell command: {e}")
            return None

    def execute_adb_command(self, adb_command):
        try:
            adb_command_list = ["adb", "-s", self.UDID, f'"{adb_command}"']
            output = subprocess.check_output(" ".join(adb_command_list), shell=True, stderr=subprocess.DEVNULL)
            return output.decode("utf-8")
        except Exception as e:
            mlog.log_func(mlog.ERROR, f"Error executing adb shell command: {e}")
            return None

    def check_wifi_state(self):
        # get WiFi information
        def get_connected_wifi_info():
            wifi_info = self.execute_adb_shell_command("ip addr show wlan0")
            if wifi_info:
                lines = wifi_info.split("\n")
                for line in lines:
                    if "inet " in line:
                        parts = line.strip().split(" ")
                        for part in parts:
                            if "." in part:
                                return part
            return None

        # check if WiFi is connected
        connected_wifi_info = get_connected_wifi_info()
        if connected_wifi_info:
            return True
        else:
            return False

    def press_home_key(self):
        try:
            subprocess.run(["adb", "-s", self.UDID, "shell", "input", "keyevent", "KEYCODE_HOME"], check=True)
        except subprocess.CalledProcessError as e:
            mlog.log_func(mlog.ERROR, f"Error executing adb command: {e}")

    def set_ip(self):
        ip_line = subprocess.check_output(f'adb -s {self.UDID} shell "ifconfig wlan0"', shell=True).decode("utf-8").split('\n')[1]
        if "inet" not in ip_line:
            mlog.log_func(mlog.ERROR, f"class error when set phone ip, please check your internet connection")
            return None

        self.ip = ip_line.split("addr:")[1].split()[0]
        return True

    def get_ip(self):
        return self.ip

    def start_tcpdump_capture(self, pcap_save_path="/data/local/tmp/1.pcap"):
        def start_capture():
            command = f'adb -s {self.UDID} shell su -c "tcpdump -i nflog:30 -w {pcap_save_path} &" &'
            os.system(command)
            time.sleep(0.5)

        # change_iptables_rules_to_mark(get_userId_of_apk())
        start_capture()
        return pcap_save_path

    def stop_tcpdump_and_pull_to_local(self, pcap_path_on_phone="/data/local/tmp/1.pcap", save_path=""):
        if not save_path:
            save_path = self.LOG_FOLDER_PATH + "1.pcap"

        def kill_tcpdump():
            pid_command = "pgrep tcpdump"
            pid = self.execute_adb_shell_command(pid_command, root=True)
            if pid:
                kill_command = f"kill -SIGINT {pid}"
                self.execute_adb_shell_command(kill_command, root=True)

        def pull_to_local():
            pull_command = f"adb -s {self.UDID} pull {pcap_path_on_phone} {save_path}"
            subprocess.run(pull_command, shell=True)

            remove_command = f"rm {pcap_path_on_phone}"
            self.execute_adb_shell_command(remove_command)

        kill_tcpdump()
        # clear_iptables_rules()
        pull_to_local()

        if not os.path.exists(save_path):
            return False
        return True

    def save_screenshot(self, figure_name="1.png"):
        self.driver.save_screenshot(figure_name)


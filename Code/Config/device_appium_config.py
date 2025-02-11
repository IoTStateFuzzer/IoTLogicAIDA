import subprocess
from Scripts.format_tools import sort_dict_by_key
from Logger import mlog
from Config.config_file import wireless_card_dict
import netifaces

phone_configs = {
    "pixel6-3": {
        # user2 remote
        "platformName": "Android",
        "deviceName": "pixel6-3",
        "udid": "1C301FDF600ELM",
        "noReset": True,
        "dontStopAppOnReset": True,
        'newCommandTimeout': "14400",
        "additionalMess": {
            "port": 4723,
            "appium_ip": "http://127.0.0.1:4723/wd/hub",
            "distance": "remote",
            "user": "user2",
            "app_posi": [400, 1600],
            "desktop_activity": ".NexusLauncherActivity",
            "unlock_password": "0000"
        }
    },
    "pixel7": {
        # user1 local
        "platformName": "Android",
        "deviceName": "pixel7",
        "udid": "2A111FDH200CJ3",
        "noReset": True,
        "dontStopAppOnReset": True,
        'newCommandTimeout': "14400",
        "additionalMess": {
            "port": 4724,
            "appium_ip": "http://127.0.0.1:4724/wd/hub",
            "distance": "local",
            "user": "user1",
            "app_posi": [400, 1600],
            "desktop_activity": ".NexusLauncherActivity",
            "unlock_password": "0000"
        }
    },
    "pixel6-1": {
        # user1 remote
        "platformName": "Android",
        "deviceName": "pixel6-1",
        "udid": "1C071FDF60020H",
        "noReset": True,
        "dontStopAppOnReset": True,
        'newCommandTimeout': "14400",
        "additionalMess": {
            "port": 4725,
            "appium_ip": "http://127.0.0.1:4725/wd/hub",
            "distance": "remote",
            "user": "user1",
            "app_posi": [400, 1600],
            "desktop_activity": ".NexusLauncherActivity",
            "unlock_password": "0000"
        }
    },
    "pixel6-2": {
        # user2 local
        "platformName": "Android",
        "deviceName": "pixel6-2",
        "udid": "26151FDF6005FT",
        "noReset": True,
        "dontStopAppOnReset": True,
        'newCommandTimeout': "14400",
        "additionalMess": {
            "port": 4726,
            "appium_ip": "http://127.0.0.1:4726/wd/hub",
            "distance": "local",
            "user": "user2",
            "app_posi": [400, 1600],
            "desktop_activity": ".NexusLauncherActivity",
            "unlock_password": "0000"
        }
    }
}

device_ip_list = [
    "224"  # tuya plug
]


def get_card_wifi_ip(interface_name):
    try:
        host_wifi_address = netifaces.ifaddresses(interface_name)
        if netifaces.AF_INET in host_wifi_address:
            return host_wifi_address[netifaces.AF_INET][0]["addr"]
    except ValueError:
        mlog.log_func(mlog.ERROR, f"No such card")
        return None


def get_phone_ip_by_adb(phone_udid):
    try:
        output = subprocess.check_output(f'adb -s {phone_udid} shell "ifconfig wlan0"', shell=True, stderr=subprocess.DEVNULL).decode("utf-8").split('\n')[1]
        if "inet" not in output:
            return None
        return output.split("addr:")[1].split()[0]
    except subprocess.CalledProcessError:
        return None


def get_phone_config_by_name(device_name):
    if device_name in phone_configs:
        return phone_configs[device_name]
    return False


def get_phone_name_list():
    return list(phone_configs.keys())


def get_phone_and_device_ip(use_manual_ip=False):
    if use_manual_ip:
        old_dict = {
            "user1": {
                "local": "10.42.1.193",
                "remote": "10.42.0.163"
            },
            "user2": {
                "local": '10.42.1.109',
                "remote": "10.42.0.244"
            },
            "devices": ["10.42.0.119"]
        }
        return old_dict

    result_dict = {}
    for phone in phone_configs:
        udid = phone_configs[phone]["udid"]
        ip = get_phone_ip_by_adb(udid)
        user = phone_configs[phone]["additionalMess"]["user"]
        distance = phone_configs[phone]["additionalMess"]["distance"]

        if user not in result_dict:
            result_dict[user] = {}
        result_dict[user][distance] = ip

    modify_device_ip = []
    host_wireless_card_ip = get_card_wifi_ip(wireless_card_dict["local"]["card"])
    if not host_wireless_card_ip:
        exit(3)
    # check device ip
    for device_ip in device_ip_list:
        try:
            if device_ip and len(device_ip.split(".")) > 1 and ".".join(device_ip.split(".")[:-1]) not in result_dict['user1']['local']:
                modify_device_ip.append(".".join(host_wireless_card_ip.split(".")[:-1]) + "." + device_ip.split(".")[-1])
            elif device_ip and len(device_ip.split(".")) == 1:
                modify_device_ip.append(".".join(host_wireless_card_ip.split(".")[:-1]) + "." + device_ip)
        except TypeError:
            mlog.log_func(mlog.ERROR,
                          "Argument of type 'NoneType' is not iterable when get_phone_and_device_ip, please check your phone")
            exit(-1)

    # add device ip list
    result_dict["devices"] = modify_device_ip

    return result_dict


def get_phone_ip_list(use_manual_ip=False):
    pd_dict = get_phone_and_device_ip(use_manual_ip)

    return_phone_ip_list = []
    for user in pd_dict:
        if "user" not in user:
            continue
        for distance in pd_dict[user]:
            if pd_dict[user][distance]:
                return_phone_ip_list.append(pd_dict[user][distance])

    return return_phone_ip_list


def get_device_ip_list(use_manual_ip=False):
    result = get_phone_and_device_ip(use_manual_ip)
    return result["devices"].copy()


def get_phone_and_device_ip_list(use_manual_ip=False):
    dict_result = get_phone_and_device_ip(use_manual_ip)
    return_list = []
    for user in dict_result:
        if user == "devices":
            return_list.extend(dict_result[user])
            continue
        for distance in dict_result[user]:
            if dict_result[user][distance]:
                return_list.append(dict_result[user][distance])
    return return_list


def get_user_distance_and_device_ip_list(user_distance_list, use_manual_ip=False):
    ip_dict = get_phone_and_device_ip(use_manual_ip)
    result = []
    result.extend(ip_dict["devices"].copy())
    for ud in user_distance_list:
        user = ud.split("|")[0]
        distance = ud.split("|")[1]

        result.append(ip_dict[user][distance])
    return result


def get_distance_ip_list(distance, use_manual_ip=False):
    result = []
    ip_dict = get_phone_and_device_ip(use_manual_ip)
    for user in ip_dict.keys():
        if "user" not in user:
            continue
        result.append(ip_dict[user][distance])

    return result


def get_user_distance_dict():
    result_dict = {}
    for phone in phone_configs:
        user = phone_configs[phone]["additionalMess"]["user"]
        distance = phone_configs[phone]["additionalMess"]["distance"]

        if user not in result_dict:
            result_dict[user] = {}
        if distance not in result_dict[user]:
            result_dict[user][distance] = phone
        else:
            return False

    for user in result_dict:
        result_dict[user] = sort_dict_by_key(result_dict[user])

    return sort_dict_by_key(result_dict)


def get_phone_or_device_abstract_name_by_ip(phone_ip, use_manual_ip=False):
    phone_ip_dict = get_phone_and_device_ip(use_manual_ip)
    for user in phone_ip_dict:
        if user == "devices" and phone_ip in phone_ip_dict[user]:
            return f"device_{phone_ip_dict[user].index(phone_ip)}"
        for distance in phone_ip_dict[user]:
            if phone_ip_dict[user][distance] == phone_ip:
                return f"{user}_{distance}"


def get_phone_did(phone):
    return phone_configs[phone]["udid"]

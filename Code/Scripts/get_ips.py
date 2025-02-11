import os
from Scripts import format_tools

ROOT_PATH = os.path.dirname(__file__)


def get_ips_by_pid(pid, device_udid):
    """
    Retrieve all IP addresses accessed by PID.
    :param pid: PID
    :return: [ip_list]
    """
    output_file = ROOT_PATH + "/output.txt"
    command = f"adb -s {device_udid} shell netstat -nlp |grep {pid} > {output_file}"
    os.system(command)

    ip_list = []
    with open(output_file, "r") as file:
        lines = file.readlines()
        for line in lines:
            if ":" in line.split()[4].split(".")[0]:
                continue
            cur_ip = ".".join(line.split()[4].split(".")[0].split("-")[1:])
            if cur_ip:
                ip_list.append(cur_ip)

    os.remove(output_file)
    ip_list = list(set(ip_list))
    return ip_list


def merge_manual_ip_list(ip_list_by_script: list, database: str, write_file=False):
    """
    Merge manual ip config list which is interesting
    :param ip_list_by_script: ip list got by netstat
    :return: merged ip list
    """
    manual_file = f"{ROOT_PATH}/../analyse_app/ui_scan_result/{database}/interesting_ip_list.txt"
    if os.path.exists(manual_file):
        merged_list = ip_list_by_script.copy()

        with open(manual_file, "r") as f:
            lines = f.readlines()
            for line in lines:
                new_ip = line.replace("\n", "")
                if new_ip and new_ip not in merged_list:
                    merged_list.append(new_ip)
        # merged_list = sorted(list(set(merged_list)))
        merged_list = format_tools.deduplicate_for_list(merged_list)

        if write_file:
            with open(manual_file, "w") as f:
                for item in merged_list:
                    f.write(item + "\n")

        return merged_list
    else:
        return None


def get_and_save_ip_list_by_apk(apk_name, device_udid, database):
    def get_pid_and_username(apk_name, device_udid):
        """
        Retrieve the PID and running username of the package named 'apk_name' when running on a mobile phone
        :param apk_name: apk_name, such as: com.x.y
        :return: pid_list->list, username->str
        """
        ps_file = ROOT_PATH + "/temp_ps.txt"
        command = f"adb -s {device_udid} shell ps |grep {apk_name} > {ps_file}"
        os.system(command)

        username = None
        pid_list = []
        with open(ps_file, "r") as file:
            temp = file.readlines()
            for line in temp:
                username = line.split()[0]
                pid_list.append(line.split()[1])

        os.remove(ps_file)

        return pid_list, username

    def get_ips_by_username(username, device_udid):
        """
        Retrieve all IP addresses accessed by username.
        :param username: username
        :return:[ip_list]
        """
        output_file = ROOT_PATH + "/output.txt"
        command = f"adb -s {device_udid} shell netstat -e |grep {username} > {output_file}"
        os.system(command)

        ip_list = []
        with open(output_file, "r") as file:
            lines = file.readlines()
            for line in lines:
                if ":" in line.split()[4].split(".")[0]:
                    continue
                cur_ip = ".".join(line.split()[4].split(".")[0].split("-")[1:])
                if cur_ip:
                    ip_list.append(cur_ip)

        os.remove(output_file)
        ip_list = list(set(ip_list))
        return ip_list

    print("Reading ip list that apk has visited")
    pid_list, username = get_pid_and_username(apk_name, device_udid)
    ip_list = get_ips_by_username(username, device_udid)
    ip_list = merge_manual_ip_list(ip_list, database, True)

    return ip_list

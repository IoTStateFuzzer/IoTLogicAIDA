import os
import shutil
import subprocess
import time
import signal

from Logger import mlog
from Config.config_file import mitm_path, system_password, wireless_card_dict
from Config.device_appium_config import get_distance_ip_list


class MitmCLs:
    def __init__(self, distance):
        # path of folders
        self.ROOT_PATH = os.path.dirname(__file__)
        self.LOG_FOLDER_PATH = self.ROOT_PATH + "/../../Logger/"
        self.PACKET_ROOT_PATH = self.ROOT_PATH + "/packets/"
        self.SCRIPTS_FOLDER = self.ROOT_PATH + "/../../Scripts/"

        # configure
        self.admin_proc = subprocess.Popen(["echo", system_password], stdout=subprocess.PIPE)
        if distance not in wireless_card_dict.keys():
            mlog.log_func(mlog.ERROR, f"Wrong distance, please select in {list(wireless_card_dict.keys())}")
            exit(-1)
        self.distance = distance
        self._WIRELESS_CARD = wireless_card_dict[self.distance]["card"]

        # set wireless card ip
        inet_output = subprocess.check_output(f"ip addr show {self._WIRELESS_CARD}", shell=True).decode('utf-8').split("\n")
        for line in inet_output:
            if "inet" in line and "brd" in line:
                self._WIRELESS_IP = line.split()[1].split('/')[0]

        # packet captured by tshark
        self.cur_packet_name = ""
        self.cur_packet_folder = ""
        self.sslkeyfilelog_path = ""

    def __del__(self):
        self.admin_proc.terminate()

    """
    iptables and mitmproxy
    """
    def _set_forward(self):
        """
        enable forward and change ip tables forward rules
        """
        mlog.log_func(mlog.LOG, f"Set iptables forward rules")
        subprocess.check_call("sudo -S sysctl -w net.ipv4.ip_forward=1".split(), stdin=self.admin_proc.stdout, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        subprocess.check_call("sudo -S sysctl -w net.ipv4.conf.all.send_redirects=0".split(), stdin=self.admin_proc.stdout, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    def _change_ip_tables(self):
        """
        enable forward and change ip tables forward rules
        """
        mlog.log_func(mlog.LOG, f"Change <{self.distance}>-<{self._WIRELESS_CARD}> iptable rules")
        dst_port = "8080" if self.distance == "local" else "8081"
        # subprocess.check_call(f"sudo -S iptables -t nat -A PREROUTING -i {self._WIRELESS_CARD} -p tcp -m multiport --dports 80,443,8883 -j REDIRECT --to-port {dst_port}".split(), stdin=self.admin_proc.stdout, stderr=subprocess.DEVNULL)
        try:
            for ip in get_distance_ip_list(self.distance):
                if not ip:
                    continue
                subprocess.check_call(f"sudo -S iptables -t nat -A PREROUTING -i {self._WIRELESS_CARD} -p tcp -s {ip} -m multiport --dports 80,443,8883 -j REDIRECT --to-port {dst_port}".split(), stdin=self.admin_proc.stdout, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            mlog.log_func(mlog.ERROR, f"Please check phone's wifi connection under <{self.distance}> wifi, someone disconnect")
            exit(2)

    def clear_ip_tables(self):
        """
        clear ip tables forward rules
        """
        mlog.log_func(mlog.LOG, "Clear customer iptables rules")
        # subprocess.run("sudo -S iptables -F PREROUTING -t nat", shell=True, stdin=self.admin_proc.stdout, stderr=subprocess.DEVNULL)
        os.system('echo %s | sudo -S %s' % (system_password, "iptables -F PREROUTING -t nat"))

    def _launch_mitm(self):
        """
        start mitmproxy
        """
        mlog.log_func(mlog.LOG, f"Start mitmproxy --- <{self.distance}>")

        self.sslkeyfilelog_path = f'{self.PACKET_ROOT_PATH}/sslkeylogfile_{self.distance}.txt'
        # create and refresh exist keylog file
        with open(self.sslkeyfilelog_path, "w") as keyfile:
            pass

        start_mitm_command = f'SSLKEYLOGFILE="{self.sslkeyfilelog_path}" {mitm_path} --mode transparent -v --ssl-insecure --tcp-host \'.*\' -p {"8080" if self.distance == "local" else "8081"}'
        self.mitm_process = subprocess.Popen(start_mitm_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True, preexec_fn=os.setsid)

    def start_mitm_main(self, change_flag=True):
        """
        start mitmproxy
        """
        if change_flag:
            self._set_forward()
        self._change_ip_tables()
        self._launch_mitm()

    def _stop_mitm_process(self, save_keylog_file_path=None):
        mlog.log_func(mlog.LOG, "Kill mitm process")

        try:
            self.mitm_process.terminate()
            os.killpg(os.getpgid(self.mitm_process.pid), signal.SIGTERM)
        except ProcessLookupError:
            mlog.log_func(mlog.ERROR, "ProcessLookupError from mitm_network.stop_mitm_process")

        # save key log file
        if save_keylog_file_path and os.path.exists("/".join(save_keylog_file_path.split("/")[:-1])) and os.path.exists(self.sslkeyfilelog_path):
            shutil.move(self.sslkeyfilelog_path, save_keylog_file_path)

    def stop_mitm_and_clear_iptables(self, save_keylog_file_path=None):
        self._stop_mitm_process(save_keylog_file_path)
        self.clear_ip_tables()

    """
    tshark
    """
    def start_tshark(self, pcapng_name):
        # set pcapng name
        self.cur_packet_name = pcapng_name.replace(".pcapng", "").replace(".pcap", "") + '_' + str(int(time.time())) + "_" + self.distance + ".pcapng"

        # create folder
        self.cur_packet_folder = self.PACKET_ROOT_PATH + "_".join(self.cur_packet_name.split("_")[:-1]) + "/" + self.cur_packet_name.split("_")[-1][:-7] + "/"
        if not os.path.exists(self.cur_packet_folder):
            os.makedirs(self.cur_packet_folder)

        mlog.log_func(mlog.LOG, f"Start capturing, save in file: {self.cur_packet_folder}{self.cur_packet_name}")
        subprocess.Popen(["tshark", "-i", self._WIRELESS_CARD, "-w", self.cur_packet_folder + self.cur_packet_name], stdout=subprocess.DEVNULL)
        # subprocess.Popen(["tcpdump", "-i", self._WIRELESS_CARD, "-w", self.cur_packet_folder + self.cur_packet_name], stdout=subprocess.DEVNULL)

        return self.cur_packet_name

    def stop_tshark(self):
        mlog.log_func(mlog.LOG, "kill capture progress")
        for line in subprocess.check_output("ps aux|grep tshark", shell=True).decode('utf-8').split('\n')[:-3]:
        # for line in subprocess.check_output("ps aux|grep tcpdump", shell=True).decode('utf-8').split('\n')[:-3]:
            pid = line.split()[1]

            command = f"kill -15 {pid}"
            os.system('echo %s | sudo -S %s' % (system_password, command))

    """
    check whether mitm starts successfully
    """
    def check_sslkey_file_size(self):
        if os.path.exists(self.sslkeyfilelog_path) and os.path.isfile(self.sslkeyfilelog_path):
            file_size = os.path.getsize(self.sslkeyfilelog_path)
            return bool(file_size)
        mlog.log_func(mlog.ERROR, f"keylog file <'{self.sslkeyfilelog_path}'> does not exist.")
        return False

    def check_pcapng_file(self):
        if os.path.exists(self.cur_packet_folder + self.cur_packet_name):
            return True
        mlog.log_func(mlog.ERROR, f"The pcapng file <'{self.cur_packet_folder + self.cur_packet_name}'> does not exist.")
        return False
        
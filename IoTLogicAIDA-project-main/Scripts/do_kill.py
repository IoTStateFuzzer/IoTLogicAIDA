import subprocess
import os

from Config.config_file import frida_server_path, system_password


def kill_tshark():
    print("kill tshark")
    output = subprocess.check_output("ps aux|grep tshark", shell=True).decode('utf-8').split('\n')[:-3]
    for line in output:
        pid = line.split()[1]

        command = f"kill -15 {pid}"
        os.system('echo %s | sudo -S %s' % (system_password, command))


def kill_tcpdump():
    print("kill tcpdump capture")
    output = subprocess.check_output("ps aux|grep tcpdump", shell=True).decode('utf-8').split('\n')[:-3]
    for line in output:
        pid = line.split()[1]

        command = f"kill -15 {pid}"
        os.system('echo %s | sudo -S %s' % (system_password, command))


def kill_appium():
    print("kill appium")
    output = subprocess.check_output("ps aux|grep appium", shell=True).decode('utf-8').split('\n')[:-3]
    for line in output:
        pid = line.split()[1]

        command = f"kill -15 {pid}"
        os.system('echo %s | sudo -S %s' % (system_password, command))


def kill_mitm():
    print("kill mitmdump")
    mitm_output = subprocess.check_output("ps aux|grep mitm", shell=True).decode('utf-8').split('\n')[:-3]
    for line in mitm_output:
        pid = line.split()[1]

        command = f"kill -15 {pid}"
        os.system('echo %s | sudo -S %s' % (system_password, command))

    os.system('echo %s | sudo -S %s' % (system_password, "iptables -F PREROUTING -t nat"))


def kill_frida():
    print("\nkill frida")
    device_list = subprocess.check_output("adb devices", shell=True).decode('utf-8').split('\n')[1:-2]
    print(device_list)
    for dev_id in device_list:
        dev_id = dev_id.split()[0]
        print(dev_id, end=" ")
        try:
            get_frida_pid_command = f"frida-ps -D {dev_id} | grep {frida_server_path.split('/')[-1]}"
            frida_pid = subprocess.check_output(get_frida_pid_command, shell=True).decode('utf-8').split()[0]

            stop_command = f'adb -s {dev_id} shell su -c "kill -9 {frida_pid}"'
            subprocess.run(stop_command, shell=True)

            print(1)
        except subprocess.CalledProcessError:
            print(0)


def kill_tcpdump_on_phone():
    print("\nkill tcpdump")
    device_list = subprocess.check_output("adb devices", shell=True).decode('utf-8').split('\n')[1:-2]
    print(device_list)
    for dev_id in device_list:
        dev_id = dev_id.split()[0]
        print(dev_id, end=" ")
        try:
            tcpdump_pid = subprocess.check_output(f"frida-ps -D {dev_id} | grep tcpdump", shell=True).decode('utf-8').split()[0]
            subprocess.run(f'adb -s {dev_id} shell su -c "kill -15 {tcpdump_pid}"', shell=True)
            subprocess.run(f'adb -s {dev_id} shell su -c "iptables -F"', shell=True)
            print(1)
        except subprocess.CalledProcessError:
            print(0)


def kill_main():
    kill_tshark()
    kill_tcpdump()
    kill_tcpdump_on_phone()
    kill_appium()
    kill_mitm()
    kill_frida()


if __name__ == "__main__":
    kill_main()
    # kill_tcpdump()
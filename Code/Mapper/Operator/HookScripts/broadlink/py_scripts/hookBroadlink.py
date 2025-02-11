#!/bin/python
import frida, sys
import json, time
import general_tools
import argparse

hooked_message_list = []


def message_handler(message, payload):
    if message['type'] == 'send':
        if message['payload'].split()[0] == 'method':
            class_name = message['payload'].split()[1].split(".")[-1]
            class_name = class_name + "_method.txt"
            print('************writing to file ' + class_name + '************************')
            file_name = general_tools.get_true_file_path(class_name)
            pay_strs = (" ".join(message['payload'].split()[2:])).split("++")
            with open(file_name, "w") as f:
                for item in pay_strs:
                    f.write(str(item.encode("utf8"))[2:-1])
                    f.write("\n")
            print('**************************finish********************************')
        elif message['payload'].split()[0] == 'view':
            print(message['payload'][5:])
        elif message['payload'].split()[0] == 'save':
            # get file name
            save_file_name = message['payload'].split()[1]
            print("[save file] --- " + save_file_name)
            # get start index
            start_index = len(message['payload'].split()[0]) + 1 + len(message['payload'].split()[1]) + 1
            save_payload = message['payload'][start_index:]
            # save
            if save_payload not in hooked_message_list:
                hooked_message_list.append(save_payload)
                save_file_name = general_tools.get_true_file_path(save_file_name)
                with open(save_file_name, "w") as f:
                    f.write(save_payload)
        elif message['payload'].split()[0] == 'read':
            file_name = message['payload'].split()[1]
            file_name = general_tools.get_true_file_path(file_name)
            with open(file_name, 'r') as f:
                data = json.load(f)
                print("read file: " + file_name)
                script.post(data)
        else:
            print("[0] {0}".format(message['payload']))
            pass
    else:
        print("***handler message***: ", message)
        print("***payload***: ", payload)
        print()


if __name__ == "__main__":
    # args: [device_id, target app name, control_flag]
    # register arguments
    arg_parser = argparse.ArgumentParser(description="Arguments for get device information when device control")
    arg_parser.add_argument('-c', '--control_distance', type=int, help="Input distance\t --local: 0, --remote: 1", required=True, choices=[0, 1])
    arg_parser.add_argument("-d", "--device_id", type=str, help="Phone udid for hook", required=True)
    arg_parser.add_argument('-a', "--app_name", type=str, help="APP name for hook", required=True)

    args = arg_parser.parse_args()

    # use frida to attach target app
    device = frida.get_device_manager().get_device(args.device_id)
    process = device.attach(args.app_name)
    script = ''

    js_list = [
        "saveDeviceTableInfo-Local.js",
        "saveDeviceTableInfo-Remote.js"
    ]

    script = general_tools.load_script(js_list[args.control_distance], script)
    print('[***] Hook Start Running')
    print('[scripts]: ', js_list[args.control_distance])

    script = process.create_script(script)
    script.on("message", message_handler)
    time.sleep(1)
    script.load()

    sys.stdin.read()

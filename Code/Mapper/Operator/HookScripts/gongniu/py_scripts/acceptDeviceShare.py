#!/bin/python
import time

import frida
import json
import config
import argparse


def control_main(device_id, target_app, knowledge_file):
    # use frida to attach target app
    device = frida.get_device_manager().get_device(device_id)
    process = device.attach(target_app)

    script = """
    Java.perform(function(){
        const gnnetwork_agent = Java.use("com.gnnetwork.GNNetworkAgent");
        let v0_1 = gnnetwork_agent.INSTANCE.value;
        let http_put = Java.use("com.gongniu.cloudapi.enums.HttpMethod").POST_BODY_JSON.value;
    
        // load device information from json file
        send("read """ + knowledge_file + """");
        var load_obj;
        recv(function (received_json_object) {
            load_obj = received_json_object;
            }).wait();
            
        let arg4 = load_obj.arg4;
        let control_uri = load_obj.control_uri;
        let control_payload = load_obj.control_payload;
        v0_1.commonRequest(control_uri, http_put, null, arg4, control_payload, null, null, null);
});
    """

    def message_handler(message, payload):
        if message['type'] == 'send':
            if message['payload'].split()[0] == 'read':
                file_name = message['payload'].split()[1]
                file_name = config.get_true_file_path(file_name)
                with open(file_name, 'r') as f:
                    data = json.load(f)
                    script.post(data)
            else:
                # print("[0] {0}".format(message['payload']))
                pass
        else:
            print("***handler message***: ", message)
            print("***payload***: ", payload)
            print()

    script = process.create_script(script)
    script.on("message", message_handler)
    script.load()


if __name__ == "__main__":
    # register arguments
    arg_parser = argparse.ArgumentParser(description="Arguments for get device information when device control")
    arg_parser.add_argument("-d", "--device_id", type=str, help="Phone udid for hook", required=True)
    arg_parser.add_argument('-a', "--app_name", type=str, help="APP name for hook", required=True)
    arg_parser.add_argument('-f', "--knowledge_file", type=str, help="Knowledge for hook", required=True)

    args = arg_parser.parse_args()

    # start_time = time.time()
    control_main(device_id=args.device_id, target_app=args.app_name, knowledge_file=args.knowledge_file)
    # print(time.time() - start_time)

#!/bin/python
import frida
import time, general_tools
import argparse


def control_main(device_id, target_app, knowledge_file):
    device = frida.get_device_manager().get_device(device_id)
    process = device.attach(target_app)
    script ="""
Java.perform(
  function(){
    const networkApiCls=Java.use("cn.com.broadlink.networkapi.NetworkAPI");
    send("read """+knowledge_file+'''");
    var requestObjs;
    recv(function(recvObj){
      requestObjs=recvObj;
    }).wait();
    let requestArgs=requestObjs.split(" ");
    var networkApiInstance = networkApiCls.getInstanceBLNetwork(null);
    networkApiInstance.dnaControl(requestArgs[0]+requestArgs[1],null,requestArgs[3].replace(/"val":0/, '"val":1'),requestArgs[4]);
})
    '''

    script = process.create_script(script)

    def message_handler(message, payload):
        if message['type'] == 'send':
            if message['payload'].split()[0] == 'read':
                file_name = message['payload'].split()[1]
                file_name = general_tools.get_true_file_path(file_name)
                with open(file_name, 'r') as f:
                    data = f.read()
                    #data.update({"controlFlag": controlFlag})
                    script.post(data)
            else:
                print("[0] {0}".format(message['payload']))
                pass
        else:
            print("***handler message***: ", message)
            print("***payload***: ", payload)
            print()

    script.on("message", message_handler)
    time.sleep(1)
    script.load()

    script ="""
Java.perform(
  function(){
    const networkApiCls=Java.use("cn.com.broadlink.networkapi.NetworkAPI");
    send("read """+knowledge_file+'''");
    var requestObjs;
    recv(function(recvObj){
      requestObjs=recvObj;
    }).wait();
    let requestArgs=requestObjs.split(" ");
    var networkApiInstance = networkApiCls.getInstanceBLNetwork(null);
    networkApiInstance.dnaControl(requestArgs[0]+requestArgs[1],null,requestArgs[3].replace(/"val":1/, '"val":0'),requestArgs[4]);
})
    '''

    script = process.create_script(script)

    def message_handler(message, payload):
        if message['type'] == 'send':
            if message['payload'].split()[0] == 'read':
                file_name = message['payload'].split()[1]
                file_name = general_tools.get_true_file_path(file_name)
                with open(file_name, 'r') as f:
                    data = f.read()
                    #data.update({"controlFlag": controlFlag})
                    script.post(data)
            else:
                print("[0] {0}".format(message['payload']))
                pass
        else:
            print("***handler message***: ", message)
            print("***payload***: ", payload)
            print()

    script.on("message", message_handler)
    time.sleep(1)
    script.load()

if __name__ == "__main__":
    # register arguments
    arg_parser = argparse.ArgumentParser(description="Arguments for get device information when device control")
    # arg_parser.add_argument('-s', '--switch_flag', type=int, help="Switch\t --off: 0, --on: 1",
    #                         required=True, choices=[0, 1])
    arg_parser.add_argument("-d", "--device_id", type=str, help="Phone udid for hook", required=True)
    arg_parser.add_argument('-a', "--app_name", type=str, help="APP name for hook", required=True)
    arg_parser.add_argument('-f', "--knowledge_file", type=str, help="Knowledge for hook", required=True)

    args = arg_parser.parse_args()
    control_main(device_id=args.device_id, target_app=args.app_name, knowledge_file=args.knowledge_file)


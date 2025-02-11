#!/bin/python
import time

import frida
import config
import argparse


def control_main(device_id, target_app, knowledge_file):
    target_app = "智能生活"
    device = frida.get_device_manager().get_device(device_id)
    process = device.attach(target_app)
    script = '''

Java.perform(function(){
 
  Java.openClassFile("/data/local/tmp/r0gson.dex").load();
  const gson = Java.use('com.r0ysue.gson.Gson');
  
  send("read '''+knowledge_file+'''");

  var requestObjs;
  recv(function(recvObj){requestObjs=recvObj;}).wait();
  var requestArgs=requestObjs.split(" ");
  

  const sandCls=Java.use("com.thingclips.smart.interior.device.confusebean.SandO");

    const cls1=Java.use("com.thingclips.sdk.device.qbdqpqq");
    cls1.bdpdqbp.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.Object', 'com.thingclips.smart.interior.device.confusebean.SandO', 'int', 'com.thingclips.smart.sdk.api.IResultCallback').implementation=function(){
    	//console.log("fucking service over"+arguments[0]+" "+arguments[1]+" "+arguments[2]+" "+arguments[3]+" "+arguments[4]+" "+arguments[5]);
       // console.log(gson.$new().toJson(arguments[6]));
    	return cls1.bdpdqbp(arguments[0],arguments[1],arguments[2],arguments[3],sandCls.$new(),arguments[5],arguments[6]);
    }

    const mqtt_cls=Java.use("com.thingclips.sdk.mqtt.bqbppdq");
    mqtt_cls.publish.overload('java.lang.String', '[B', 'com.thingclips.smart.sdk.api.IResultCallback').implementation=function(){
        //console.log(arguments[0]+"!!!!!!!!!!!!!!!"+arguments[1]+"!!!!!!!!!!!!!!!!!!!"+arguments[2]);
        return this.publish(arguments[0],arguments[1],arguments[2]);
    }
    
    const byte_cls=Java.use("com.thingclips.sdk.mqtt.bpqqdpq");
    byte_cls.$init.implementation=function(){
        //console.log("once++++++++"+gson.$new().toJson(arguments[0]));
        return this.$init(arguments[0]);
    }

    

    const callback_cls=Java.use("com.thingclips.smart.sdk.api.IResultCallback");
    const json_cls=Java.use("com.alibaba.fastjson.JSONObject");


    var mycall_back = Java.registerClass({
        implements: [callback_cls],
        methods: {
          onError(chain, authType) {
            console.log("on error");
          },
          onSuccess(){
            console.log("success");
          }
        },
        name: "com.sensepost.test.TrustManager",
    });
    //
    const sleep = (delay) => new Promise((resolve) => setTimeout(resolve, delay));
    const repeatedGreetings = async () => {
        //console.log("First");
        //await sleep(3000);
        var new_json=json_cls.parse(requestArgs[3].replace('false','true'));
        cls1.bdpdqbp.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.Object', 'com.thingclips.smart.interior.device.confusebean.SandO', 'int', 'com.thingclips.smart.sdk.api.IResultCallback').call(cls1,requestArgs[0],requestArgs[1],requestArgs[2], new_json,sandCls.$new(), 5,null);
        await sleep(1000);
        var new_json2=json_cls.parse(requestArgs[3].replace('true',false));
        cls1.bdpdqbp.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.Object', 'com.thingclips.smart.interior.device.confusebean.SandO', 'int', 'com.thingclips.smart.sdk.api.IResultCallback').call(cls1,requestArgs[0],requestArgs[1],requestArgs[2], new_json2,sandCls.$new(), 5,null);
    }
    repeatedGreetings();
});
    '''
    script = process.create_script(script)
    

    def message_handler(message, payload):
        if message['type'] == 'send':
            if message['payload'].split()[0] == 'read':
                file_name = message['payload'].split()[1]
                file_name = config.get_true_file_path(file_name)
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
    script.load()
    time.sleep(4)


if __name__ == "__main__":
    # register arguments
    arg_parser = argparse.ArgumentParser(description="Arguments for get device information when device control")
    # arg_parser.add_argument('-s', '--switch_flag', type=int, help="Switch\t --off: 0, --on: 1",
    #                         required=True, choices=[0, 1])
    arg_parser.add_argument("-d", "--device_id", type=str, help="Phone udid for hook", required=True)
    arg_parser.add_argument('-a', "--app_name", type=str, help="APP name for hook", required=True)
    arg_parser.add_argument('-f', "--knowledge_file", type=str, help="Knowledge for hook", required=True)

    args = arg_parser.parse_args()
    # control_main(device_id=args.device_id, controlFlag=args.switch_flag, target_app=args.app_name, knowledge_file=args.knowledge_file)
    control_main(device_id=args.device_id, target_app=args.app_name, knowledge_file=args.knowledge_file)

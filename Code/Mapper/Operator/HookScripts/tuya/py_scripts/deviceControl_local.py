#!/bin/python
import time

import frida
import config
import argparse


def control_main(device_id, target_app, knowledge_file):
    target_app = "com.tuya.smartlifeiot:monitor"
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
  

  const transfer_cls=Java.use("com.thingclips.smart.android.hardware.service.DevTransferService");
  transfer_cls.buildConnect.implementation=function(){
    console.log("build connect=>"+gson.$new().toJson(arguments[0])+" "+arguments[1]);
    return transfer_cls.buildConnect.apply(this,arguments);
  }
  transfer_cls.controlByBinary.implementation=function(){
    console.log("control by binary=>"+arguments[0]+" "+arguments[1]+" "+arguments[2]);
    var retvar=this.controlByBinary.apply(this,arguments);
    console.log("controlByBinary return=>"+retvar);
    return retvar;
  }
  transfer_cls.addDev.implementation=function(){
    console.log("add dev=>"+gson.$new().toJson(arguments[0])+" "+arguments[1]);
    return transfer_cls.addDev.apply(this,arguments);
  }
  
  const wrapper_cls=Java.use("com.thingclips.smart.android.device.ThingNetworkInterface");
  const inner_cls=Java.use("com.thingclips.smart.android.device.ThingNetworkApi");
  const gwbean_cls=Java.use("com.thingclips.smart.android.hardware.bean.HgwBean");


  var did=requestArgs[0];
  var key=requestArgs[1];
  var gateway_bin_str=requestArgs[2];
  let timeStamp=new Date().getTime().toString();
  var command_str='{"devId":"'+did+'","uid":"ay1698756086060AheGn","t":'+timeStamp.substring(0,10)+',"dps":{"1":true}}';
  var command_str2='{"devId":"'+did+'","uid":"ay1698756086060AheGn","t":'+timeStamp.substring(0,10)+',"dps":{"1":false}}';
  //console.log(command_str);

  var fake_gwbean=gwbean_cls.$new();
  var gateway_bin_json=JSON.parse(gateway_bin_str);
  console.log(gateway_bin_json.gwId);
  fake_gwbean.ablilty.value=gateway_bin_json.ablilty;
  fake_gwbean.active.value=gateway_bin_json.active;
  fake_gwbean.apConfigType.value=gateway_bin_json.apConfigType;
  fake_gwbean.encrypt.value=gateway_bin_json.encrypt;
  fake_gwbean.extend.value=gateway_bin_json.extend;
  fake_gwbean.gwId.value=gateway_bin_json.gwId;
  fake_gwbean.ip.value=gateway_bin_json.ip;
  fake_gwbean.lastSeenTime.value=gateway_bin_json.lastSeenTime;
  fake_gwbean.mode.value=gateway_bin_json.mode;
  fake_gwbean.proAbility.value=gateway_bin_json.proAbility;
  fake_gwbean.productKey.value=gateway_bin_json.productKey;
  fake_gwbean.sl.value=gateway_bin_json.sl;
  fake_gwbean.ssid.value=gateway_bin_json.ssid;
  fake_gwbean.token.value=gateway_bin_json.token;
  fake_gwbean.uuid.value=gateway_bin_json.uuid;
  fake_gwbean.version.value=gateway_bin_json.version;
  fake_gwbean.wf_cfg.value=gateway_bin_json.wf_cfg;

  const sleep = (delay) => new Promise((resolve) => setTimeout(resolve, delay));

  const repeatedGreetings = async () => {
    await sleep(1000);
    Java.choose('com.thingclips.smart.android.hardware.service.DevTransferService',{
        onMatch:function(instance){
            console.log("dtf service"+instance);
            console.log(gson.$new().toJson(fake_gwbean));
            instance.addDev(fake_gwbean,null);
        },
        onComplete:function(){
            console.log("dtf service complete");
        }
    });
    await sleep(1000);
    var hdr=[51,46,51,0,0,0,0,0,0,0,5,0,0,0,0];
    var send_bytes=inner_cls.encryptAesData(command_str,key);
    
    var originalArray = new Uint8Array(send_bytes.length);
    for (var i = 0; i < send_bytes.length; i++) {
        originalArray[i] = send_bytes[i];
    }
    var jsUint8Array = new Uint8Array(hdr);
    var concatenatedArray = new Uint8Array(originalArray.length + jsUint8Array.length);
    concatenatedArray.set(jsUint8Array, 0);
    concatenatedArray.set(originalArray, jsUint8Array.length);
    var ja=Java.array('byte',concatenatedArray);
    console.log("array=>"+ja+" "+ja.length);
    
    var result=wrapper_cls.sendBytes(ja,ja.length,7,did);
    console.log("sendBytes result:"+result);
    await sleep(1000);

    var send_bytes2=inner_cls.encryptAesData(command_str2,key);
    var originalArray2 = new Uint8Array(send_bytes2.length);
    for (var i = 0; i < send_bytes2.length; i++) {
        originalArray2[i] = send_bytes2[i];
    }
    var jsUint8Array2 = new Uint8Array(hdr);
    var concatenatedArray2 = new Uint8Array(originalArray2.length + jsUint8Array2.length);
    concatenatedArray2.set(jsUint8Array2, 0);
    concatenatedArray2.set(originalArray2, jsUint8Array2.length);
    var ja2=Java.array('byte',concatenatedArray2);
    console.log("array=>"+ja2+" "+ja2.length);
    var result2=wrapper_cls.sendBytes(ja2,ja2.length,7,did);
    console.log("sendBytes result:"+result2);

    
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

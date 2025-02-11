#!/bin/python
import frida
import json
import time, Config
import argparse


def control_main(device_id, target_app, knowledge_file):
    device = frida.get_device_manager().get_device(device_id)
    process = device.attach(target_app)
    script = '''
    
Java.perform(function(){
  const data_qrcode_cls=Java.use("cn.com.broadlink.unify.libs.data_logic.family.service.data.DataQrCode");
  send("read '''+knowledge_file+'''");
  var request_objs;
  recv(function(recv_obj){
    request_objs=JSON.parse(recv_obj);
  }).wait();
  console.log(request_objs['qrcode']);
  
  var qr_data=data_qrcode_cls.$new();
  //console.log(qr_data);
  qr_data.setQrcode(request_objs['qrcode']);
  const creater_cls=Java.use("cn.com.broadlink.unify.libs.data_logic.family.service.FamilyService$Creater");
  console.log(creater_cls);
  const Boolean_cls=Java.use("java.lang.Boolean");
  var true_value=Boolean_cls.$new(true);
  var boolean_array=Java.array('java.lang.Boolean',[true_value]);
  //boolean_array[0]=Boolean_cls.valueOf(true);
  console.log(boolean_array);
  var family_service=creater_cls.newService(boolean_array);
  //console.log(family_service.joinFamilyByQrCode);
  family_service.joinFamilyByQrCode(qr_data);

});
    
    '''

    script = process.create_script(script)

    def message_handler(message, payload):
        if message['type'] == 'send':
            if message['payload'].split()[0] == 'read':
                file_name = message['payload'].split()[1]
                file_name = Config.get_true_file_path(file_name)
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
    arg_parser.add_argument("-d", "--device_id", type=str, help="Phone udid for hook", required=True)
    arg_parser.add_argument('-a', "--app_name", type=str, help="APP name for hook", required=True)
    arg_parser.add_argument('-f', "--knowledge_file", type=str, help="Knowledge for hook", required=True)

    args = arg_parser.parse_args()
    control_main(device_id=args.device_id, target_app=args.app_name, knowledge_file=args.knowledge_file)


#!/bin/python
import frida
import time, config
import argparse


def control_main(controlFlag, device_id, target_app, knowledge_file):
    device = frida.get_device_manager().get_device(device_id)
    process = device.attach(target_app)
    script = '''

Java.perform(function(){
  const get_context_cls=Java.use("com.xiaomi.smarthome.application.ServiceApplication");
  var context=get_context_cls.getAppContext();
  
  send("read '''+knowledge_file+'''");
  var requestObjs;
  recv(function(recvObj){
    requestObjs=recvObj;
  }).wait();
  let obj = JSON.parse(requestObjs);
  obj.mMap.result.OooOo0 = JSON.parse(obj.mMap.result.OooOo0);
  var inv_id=(obj.mMap.result.OooOo0.result.messages[0].params.inv_id);
  var msg_id=(obj.mMap.result.OooOo0.result.messages[0].msg_id);
  //console.log(typeof(inv_id)+" "+typeof(msg_id));
  const accept_cls=Java.use("_m_j.cd8");
  accept_cls.OooOO0O(context,inv_id,msg_id.toString(),null);
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
    time.sleep(1)
    script.load()


if __name__ == "__main__":
    # register arguments
    arg_parser = argparse.ArgumentParser(description="Arguments for get device information when device control")
    arg_parser.add_argument('-s', '--switch_flag', type=int, help="Switch\t --off: 0, --on: 1",
                            required=True, choices=[0, 1])
    arg_parser.add_argument("-d", "--device_id", type=str, help="Phone udid for hook", required=True)
    arg_parser.add_argument('-a', "--app_name", type=str, help="APP name for hook", required=True)
    arg_parser.add_argument('-f', "--knowledge_file", type=str, help="Knowledge for hook", required=True)

    args = arg_parser.parse_args()
    control_main(device_id=args.device_id, controlFlag=args.switch_flag, target_app=args.app_name, knowledge_file=args.knowledge_file)

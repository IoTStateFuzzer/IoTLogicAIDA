#!/bin/python
import frida
import config
import argparse


def control_main(device_id, target_app, knowledge_file):
    device = frida.get_device_manager().get_device(device_id)
    pid = device.spawn(['com.xiaomi.smarthome'])
    #time.sleep(1)
    process = device.attach(pid)
    script = '''
    var pk=[];
var sk=[];
Java.perform(function(){
  function ab2str(arrayBuffer){
    return String.fromCharCode.apply(null,new Uint8Array(arrayBuffer));
  }

  Java.openClassFile("/data/local/tmp/r0gson.dex").load();
  const gson = Java.use('com.r0ysue.gson.Gson');
  const mi_stream_cls=Java.use("com.xiaomi.mistream.MIStream");
  const mihome_export_config_cls=Java.use("com.xiaomi.smarthome.application.SHApplication");
  mihome_export_config_cls.exportAppBuildConfig.implementation=function(){
    console.log("[D]called export config cls");
    this.exportAppBuildConfig();
    release_cls.OooO0oO.value=false;
    return;
  }
  const decode_cls=Java.use("com.tencent.mmkv.MMKV");
  decode_cls.decodeBool.overload('java.lang.String', 'boolean').implementation=function(){
    //console.log("fucking arg=>"+arguments[0]);
    if(arguments[0]=='rn_debug_force_plaintext_transmission'){
      return true;
    }
    return this.decodeBool(arguments[0],arguments[1]);
  }
  const list_cls=Java.use("java.util.ArrayList");
  const protocol_cls=Java.use("okhttp3.Protocol");
  const builder_cls=Java.use("okhttp3.OkHttpClient$Builder");
  const obj_cls=Java.use("java.lang.Object");
  builder_cls.protocols.implementation=function(){
    console.log(Java.cast(arguments[0],list_cls));
    var list_obj=list_cls.$new();

    list_obj.add(Java.cast(protocol_cls.HTTP_1_1.value,obj_cls));
    console.log(list_obj);

    return this.protocols(Java.cast(list_obj,Java.use("java.util.List")));
  }
    function hook_sendto_content(){
        var log_cls;
        var throwable_cls;
        //let sendto_addr=Module.getBaseAddress("libmiss.so");
        //sendto_addr=sendto_addr.add("0xace4");
        //console.log(hexdump(sendto_addr, { length: 0x20, ansi: true }));
        let sendto_addr=Module.getExportByName("libmiss.so","miss_log_printf");
        var backtrace_str;
        console.log(sendto_addr);
        Interceptor.attach(sendto_addr,{
            onEnter: function(args){
                //console.log(backtrace_str);
                //console.log(args[1]);
                let buffer_addr=new NativePointer("0x"+args[3].toString(16));
                //console.log(hexdump(buffer_addr, { length: 64, ansi: true }));

                var text="miss_client_session_open OUT";
                var read_byte=buffer_addr.readByteArray(28);
                var read_str=ab2str(read_byte);
                //console.log(read_str);
                if(read_str==text){
                    let session_chunk_addr=new NativePointer("0x"+args[4].toString(16));
                    let pk_addr=session_chunk_addr.add("596");
                    let sk_addr=session_chunk_addr.add("628");

                    pk_addr.writeByteArray(pk);
                    sk_addr.writeByteArray(sk);
                    console.log("rewrite the pk and sk");
                }
            }
            ,
            onLeave: function(result){
            }
        });
    }

    setImmediate(hook_sendto_content);
    //setImmediate(hook_sign_content);*/
    //let net_res_cls=Java.use("com.xiaomi.smarthome.core.entity.net.NetResult")
    const release_cls=Java.use("_m_j.hh3");



  var arrlist_cls=Java.use("java.util.ArrayList");
  var trusted_manage_cls=Java.use("com.android.org.conscrypt.TrustManagerImpl");
  trusted_manage_cls.checkTrustedRecursive.implementation=function (certs, host, clientAuth, untrustedChain,
                                                                    trustAnchorChain, used) {
    let log_cls=Java.use("android.util.Log");
    let throwable_cls=Java.use("java.lang.Throwable");
    let backtrace_str=log_cls.getStackTraceString(throwable_cls.$new());
    //console.log(backtrace_str);
    console.log("[*] TrustManagerImpl.checkTrustedRecursive(), not throwing an exception.")
    return arrlist_cls.$new();
  };
  var pinner_cls = Java.use("okhttp3.CertificatePinner");
  pinner_cls.check.overload("java.lang.String", "java.util.List").implementation=function(a,b){
    console.log("[*] OkHTTP 3.x CertificatePinner.check(), not throwing an exception.")
    return;
  }
  var x509manager_cls=Java.use("javax.net.ssl.X509TrustManager");
  var ssl_context_cls=Java.use("javax.net.ssl.SSLContext");

  var X509TrustManagert = Java.registerClass({
    implements: [x509manager_cls],
    methods: {
      // tslint:disable-next-line:no-empty
      checkClientTrusted(chain, authType) { },
      // tslint:disable-next-line:no-empty
      checkServerTrusted(chain, authType) { },
      getAcceptedIssuers() {
        return [];
      },
    },
      name: "com.sensepost.test.TrustManager",
    });
  var TrustManagers = [X509TrustManagert.$new()];
  var SSLContextInit=ssl_context_cls.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
  SSLContextInit.implementation=function(keyManager, trustManager, secureRandom){
     console.log("[*]SSLContextInit overriding TrustManager with empty one");
     SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
  }
    send("read '''+knowledge_file+'''");
    var requestObjs;
    recv(function(recvObj){requestObjs=recvObj;}).wait();

    var requestArgs=requestObjs.split("@@@");
    var device_state=requestArgs[0];
    var pk_sk=requestArgs[1];
    var vendor_info=requestArgs[2];
    const stat_cls=Java.use("com.xiaomi.smarthome.device.api.DeviceStat");

    var state_obj=JSON.parse(device_state);

    var key_obj=JSON.parse('{'+pk_sk+'}');
    pk=key_obj.pk;
    sk=key_obj.sk;
    const host_api_cls=Java.use("com.xiaomi.smarthome.framework.plugin.mpk.PluginHostApiImpl");
    const json_cls=Java.use("org.json.JSONObject");

    host_api_cls.getDeviceByDid.implementation=function(){
      var device_stat=this.getDeviceByDid(arguments[0]);
      //var json_stat=gson.$new().toJson(device_stat);
      var stat_obj=stat_cls.$new();
      //console.log(state_obj);
      stat_obj.authFlag.value=state_obj.authFlag;
      stat_obj.bindFlag.value=state_obj.bindFlag;
      stat_obj.bssid.value=state_obj.bssid
      stat_obj.comFlag.value=state_obj.comFlag;
      stat_obj.deviceIconReal.value=state_obj.deviceIconReal;
      stat_obj.did.value=state_obj.did;
      stat_obj.event.value= JSON.stringify(state_obj.event);//'{"prop.2.1":true}';
      stat_obj.extrainfo.value=JSON.stringify(state_obj.extrainfo);
      stat_obj.freqFlag.value=state_obj.freqFlag;
      stat_obj.hideMode.value=state_obj.hideMode;
      stat_obj.ip.value=state_obj.ip;
      stat_obj.isGrouped.value=state_obj.isGrouped;
      stat_obj.isNew.value=state_obj.isNew;
      stat_obj.isOnline.value=state_obj.isOnline;
      stat_obj.isSetPinCode.value=state_obj.isSetPinCode;
      stat_obj.lastModified.value=state_obj.lastModified;
      stat_obj.latitude.value=state_obj.latitude;
      stat_obj.location.value=state_obj.location;
      stat_obj.longitude.value=state_obj.longitude;
      stat_obj.mac.value=state_obj.mac;
      stat_obj.meshId.value=state_obj.meshId;
      stat_obj.model.value=state_obj.model;
      stat_obj.mtu.value=state_obj.mtu;
      stat_obj.name.value=state_obj.name;
      stat_obj.orderTimeJString.value=state_obj.orderTimeJString;
      stat_obj.ownerId.value=state_obj.ownerId;
      stat_obj.ownerName.value=state_obj.ownerName;
      stat_obj.parentId.value=state_obj.parentId;
      stat_obj.parentModel.value=state_obj.parentModel;
      stat_obj.permitLevel.value=state_obj.permitLevel;
      stat_obj.pid.value=state_obj.pid;
      stat_obj.pinCodeType.value=state_obj.pinCodeType;
      stat_obj.propInfo=json_cls.$new(JSON.stringify(state_obj.propInfo));
      stat_obj.resetFlag.value=state_obj.resetFlag;
      stat_obj.rssi.value=state_obj.rssi;
      stat_obj.showMode.value=state_obj.showMode;
      stat_obj.specUrn.value=state_obj.specUrn;//"urn:miot-spec-v2:device:camera:0000A01C:chuangmi-ipc019:1";
      stat_obj.ssid.value=state_obj.ssid;//"redmi_lbd";
      stat_obj.token.value=state_obj.token;//"6e436c55526955637a67616566634c71";
      stat_obj.userId.value=state_obj.userId;//"1207363361";
      stat_obj.version.value=state_obj.version;//"4.0.9_0428";
      //console.log("!!!!!!!!!!!!!!");
      //return gson.$new().fromJson(stat_str,stat_cls.$new().getClass());
      //console.log("fake=>"+gson.$new().toJson(stat_obj));
      return stat_obj;
      //return device_stat;

    }

    let best_cls=Java.use("com.xiaomi.mistream.MIStream$1");
    best_cls.onFailure.implementation=function(arg1,arg2){
        console.log("turn to success");
        return this.onSuccess(json_cls.$new(vendor_info));
    }
    const camera_api_cls=Java.use("com.xiaomi.smarthome.framework.plugin.rn.viewmanager.camera.RNCameraManagerModule");
    const sleep = (delay) => new Promise((resolve) => setTimeout(resolve, delay));

    const X509TrustManager = Java.use('com.facebook.react.bridge.Callback');

    const MyTrustManager = Java.registerClass({
        name: 'com.example.my6',
        implements: [X509TrustManager],
        methods: {
            invoke(chain) {
                //console.log("invoke");
            }
        }
    });
    const repeatedGreetings = async () => {
        console.log("First");
        await sleep(2000);
        Java.choose('com.xiaomi.mistream.XmStreamClient',{
          onMatch:function(instance){
            //console.log("instance "+instance);
            instance.streamStop(null);

          },
          onComplete:function(){
            console.log("mem scan finish");
          }
        });
        await sleep(2000);
        camera_api_cls.lambda$startConnect$0("369647111","connectionCallBack");
        await sleep(3000);
        console.log("Second");
        camera_api_cls.lambda$sendServerCmd$1("369647111",274,'{"operation":3}',MyTrustManager.$new());

    }
    repeatedGreetings();
  });
    '''
    #with open("../js_scripts/deviceControlMi.js") as f:
        #script = process.create_script(f.read())
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
    #time.sleep(1)
    script.load()
    device.resume(pid)
    input()


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

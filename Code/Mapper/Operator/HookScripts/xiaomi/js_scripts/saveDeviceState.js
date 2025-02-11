Java.perform(function(){
  const release_cls=Java.use("_m_j.hh3");
  const mihome_export_config_cls=Java.use("com.xiaomi.smarthome.application.SHApplication");
  mihome_export_config_cls.exportAppBuildConfig.implementation=function(){
    console.log("[D]called export config cls");
    this.exportAppBuildConfig();
    release_cls.OooO0oO.value=false;
    return;
  }
  const decode_cls=Java.use("com.tencent.mmkv.MMKV");
  decode_cls.decodeBool.overload('java.lang.String', 'boolean').implementation=function(){
    console.log("fucking arg=>"+arguments[0]);
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
    function ab2str(arrayBuffer){
      return String.fromCharCode.apply(null,new Uint8Array(arrayBuffer));
    }

    Java.openClassFile("/data/local/tmp/r0gson.dex").load();
    const gson = Java.use('com.r0ysue.gson.Gson');



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
    const mi_stream_cls=Java.use("com.xiaomi.mistream.MIStream");
    mi_stream_cls.missRpcProcess.implementation=function(arg1,arg2){

      return this.missRpcProcess(arg1,arg2);
    }

    var global_save_state="";
    var has_pk_sk=false;
    var has_device_state=false;
    var has_vendor_state=false;
    var has_saved=false;
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
                let buffer_addr=new NativePointer("0x"+args[3].toString(16));
                //let buffer_addr=new NativePointer("0x"+args[3].toString(16));
                //console.log(hexdump(buffer_addr, { length: 64, ansi: true }));
                var text="miss_client_session_open OUT";

                var read_byte=buffer_addr.readByteArray(28);
                var read_str=ab2str(read_byte);
                
                if(read_str==text){
                    let session_chunk_addr=new NativePointer("0x"+args[4].toString(16));
                    let pk_addr=session_chunk_addr.add("596");
                    let sk_addr=session_chunk_addr.add("628");
                    //console.log(hexdump(pk_addr, { length: 32, ansi: true }));
                    //console.log(hexdump(sk_addr, { length: 32, ansi: true }));
                    
                    var pk=new Array();
                    for(var i=0;i<32;i++){
                        pk[i]=pk_addr.readU8();
                        pk_addr=pk_addr.add("0x1");
                    }
                    var sk=new Array();
                    for(var i=0;i<32;i++){
                        sk[i]=sk_addr.readU8();
                        sk_addr=sk_addr.add("0x1");
                    }
                    //console.log(pk);
                    //console.log(sk);
                    
                    let timeStamp=new Date().getTime().toString(); 
                    if(!has_pk_sk){
                      global_save_state=global_save_state+'"pk":['+pk.toString()+'],"sk":['+sk.toString()+']'+"@@@";
                      console.log("save pk_sk");
                      has_pk_sk=true;
                    }
                    if(has_device_state && has_pk_sk && has_vendor_state && !has_saved){
                      send("save user2|local|DeviceState_"+timeStamp+".json "+global_save_state);
                      has_saved=true;
                    }
                }
            }
            ,
            onLeave: function(result){
                //let buffer_addr=new NativePointer("0x"+this.context.r1.toString(16));
                //console.log(buffer_addr);
                //console.log(hexdump(buffer_addr, { length: result.toInt32(), ansi: true }));
            }
        })
    }
    var vendor_info='';
    function hook_parse_content(){
      var log_cls;
      var throwable_cls;
      //let sendto_addr=Module.getBaseAddress("libmiss.so");
      //sendto_addr=sendto_addr.add("0xace4");
      //console.log(hexdump(sendto_addr, { length: 0x20, ansi: true }));
      let get_vendor_addr=Module.getExportByName("libmiss.so","miss_json_get_vendor");
      var backtrace_str;
      console.log(get_vendor_addr);
      Interceptor.attach(get_vendor_addr,{
        onEnter: function(args){
          let info_addr=new NativePointer("0x"+args[0].toString(16));
          while(info_addr.readU8()!=0x0){
            vendor_info=vendor_info+String.fromCharCode(info_addr.readU8());
            info_addr=info_addr.add("0x1");
          }
          let timeStamp=new Date().getTime().toString();
          if(!has_vendor_state){
            global_save_state=global_save_state+vendor_info+"@@@";
            console.log("save vendor");
            has_vendor_state=true;
          }
          if(has_device_state && has_pk_sk && has_vendor_state && !has_saved){
            send("save user2|local|DeviceState_"+timeStamp+".json "+global_save_state);
            has_saved=true;
          }
        }
        ,
        onLeave: function(result){

        }
      })
    }
    setImmediate(hook_sendto_content);
    setImmediate(hook_parse_content);

   

    const stat_cls=Java.use("com.xiaomi.smarthome.device.api.DeviceStat");
    const host_api_cls=Java.use("com.xiaomi.smarthome.framework.plugin.mpk.PluginHostApiImpl");
    const json_cls=Java.use("org.json.JSONObject");
    host_api_cls.getDeviceByDid.implementation=function () {
        var device_stat=this.getDeviceByDid(arguments[0]);
        var json_stat=gson.$new().toJson(device_stat);
         
      if(!has_device_state){
        global_save_state=global_save_state+json_stat+"@@@";
        console.log("save stat")
        has_device_state=true;
      }
      if(has_device_state && has_pk_sk && has_vendor_state && !has_saved){
        send("save user2|local|DeviceState_"+timeStamp+".json "+global_save_state);
        has_saved=true;
      }
      return host_api_cls.getDeviceByDid.apply(this,arguments);
    }

    mi_stream_cls.missCommandSend.implementation=function(){
      //console.log("command=>"+arguments[0]+" "+arguments[1]);
      return mi_stream_cls.missCommandSend.apply(this,arguments);
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
        //console.log("First");
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
        await sleep(4000);
        camera_api_cls.lambda$startConnect$0("369647111","connectionCallBack");

        await sleep(3000);
        //console.log("Second");
        camera_api_cls.lambda$sendServerCmd$1("369647111",274,'{"operation":3}',MyTrustManager.$new());
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
        
    }
    repeatedGreetings();

});

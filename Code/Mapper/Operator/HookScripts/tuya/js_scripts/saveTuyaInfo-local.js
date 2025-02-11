Java.perform(function(){
  Java.openClassFile("/data/local/tmp/r0gson.dex").load();
  const gson = Java.use('com.r0ysue.gson.Gson');
  
  var save_did=false;
  var save_key=false;
  var save_hgw=false;
  var did="";
  var key="";
  var hgw="";
  var gen_save=false;
  
  const beanget_cls=Java.use("com.thingclips.sdk.device.pdpbbqb");

  const sleep = (delay) => new Promise((resolve) => setTimeout(resolve, delay));
  const repeatedGreetings = async () => {
    await sleep(8000);
    var beanget_instance=beanget_cls.bdpdqbp();
    //console.log(beanget_instance);
    var bean=beanget_instance.getDev(did);
    console.log(gson.$new().toJson(bean));
    if(bean!=null){
      var gwbean=bean.getHgwBean();
      console.log(gson.$new().toJson(gwbean));
        if(!save_hgw){
          hgw=gson.$new().toJson(gwbean);
          save_hgw=true;
        }
        if(save_did && save_key && save_hgw && !gen_save){
          gen_save=true;
          let timeStamp=new Date().getTime().toString();
          send("save user2|local|DeviceControl_"+timeStamp+".json "+did+" "+key+" "+hgw);
        }
    }
    

  }
  //repeatedGreetings();
  

  const udp_cls=Java.use("com.thingclips.sdk.hardware.bean.HResponse");
  udp_cls.getDevId.implementation=function(){
    console.log("dev id get");
    if(!save_did){
      did=this.getDevId();
      save_did=true;
    }
    if(save_did && save_key && save_hgw && !gen_save){
      gen_save=true;
      let timeStamp=new Date().getTime().toString();
      send("save user2|local|DeviceControl_"+timeStamp+".json "+did+" "+key+" "+hgw);
    }
    if(!save_hgw){
      var beanget_instance=beanget_cls.bdpdqbp();
      //console.log(beanget_instance);
      var bean=beanget_instance.getDev(did);
      //console.log(gson.$new().toJson(bean));
        if(bean!==null){
          var gwbean=bean.getHgwBean();
          hgw=gson.$new().toJson(gwbean);
          save_hgw=true;
        }
        if(save_did && save_key && save_hgw && !gen_save){
          gen_save=true;
          let timeStamp=new Date().getTime().toString();
          send("save user2|local|DeviceControl_"+timeStamp+".json "+did+" "+key+" "+hgw);
        }
    }

    return did;
  }
  const udpp_cls=Java.use("com.thingclips.sdk.device.dqbdpqb");
  udpp_cls.getLocalKey.implementation=function(){
    console.log("key get");
    if(!save_key){
      key=this.getLocalKey(arguments[0]);
      save_key=true;
    }
    if(save_did && save_key && save_hgw && !gen_save){
      gen_save=true;
      let timeStamp=new Date().getTime().toString();
      send("save user2|local|DeviceControl_"+timeStamp+".json "+did+" "+key+" "+hgw);
    }
    return key;
  }

});

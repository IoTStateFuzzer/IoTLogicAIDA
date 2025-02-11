Java.perform(function(){
    Java.openClassFile("/data/local/tmp/r0gson.dex").load();
    const gson = Java.use('com.r0ysue.gson.Gson');
    var first_catch = false;
    let core_api_cls=Java.use("com.xiaomi.smarthome.core.server.CoreApiStub");
    let rev_cls=Java.use("_m_j.vs");
    rev_cls.OooO0OO.implementation=function(){
        //console.log("cloud------->app");
        //console.log(gson.$new().toJson(arguments[1]));
      var reply_bundle_str=gson.$new().toJson(arguments[1]);
      if(reply_bundle_str.indexOf('inv_id') !== -1 && !first_catch){
        console.log("save share_msg");
        let timeStamp=new Date().getTime().toString();
        send("save user2|local|ShareDevice_"+timeStamp+".json "+reply_bundle_str);
        first_catch = true;
      }
      return rev_cls.OooO0OO.apply(this,arguments);
    }
});
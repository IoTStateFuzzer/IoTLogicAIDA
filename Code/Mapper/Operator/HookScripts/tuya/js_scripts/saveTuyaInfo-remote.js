Java.perform(function(){
    Java.openClassFile("/data/local/tmp/r0gson.dex").load();
    const gson = Java.use('com.r0ysue.gson.Gson');
    const sandCls=Java.use("com.thingclips.smart.interior.device.confusebean.SandO");

    const cls1=Java.use("com.thingclips.sdk.device.qbdqpqq");
    cls1.bdpdqbp.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.Object', 'com.thingclips.smart.interior.device.confusebean.SandO', 'int', 'com.thingclips.smart.sdk.api.IResultCallback').implementation=function(){
        let timeStamp=new Date().getTime().toString();
        var c=arguments[3];
        //console.log(c);
        if(c.toString().indexOf("dps")!=-1){
            send("save user2|remote|DeviceControl_"+timeStamp+".json "+arguments[0]+" "+arguments[1]+" "+arguments[2]+" "+arguments[3]);
        }
        return cls1.bdpdqbp(arguments[0],arguments[1],arguments[2],arguments[3],arguments[4],arguments[5],arguments[6]);
    }
});
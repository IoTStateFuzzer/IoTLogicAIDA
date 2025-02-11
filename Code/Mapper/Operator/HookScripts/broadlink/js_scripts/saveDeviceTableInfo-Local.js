Java.perform(
  function(){
    const networkApiCls=Java.use("cn.com.broadlink.networkapi.NetworkAPI");
    networkApiCls.dnaControl.implementation=function(){
      let timeStamp=new Date().getTime().toString();
      let jsonObj=JSON.parse(arguments[2]);
      if(jsonObj['vals']!=''){
        send("save user2|local|DeviceControl_"+timeStamp+".json "+arguments[0]+" "+arguments[1]+" "+arguments[2]+" "+arguments[3]);
        //console.log(arguments[0]+" "+arguments[1]+" "+arguments[2]+" "+arguments[3])
      }
      return networkApiCls.dnaControl.apply(this,arguments);
    }
  }
)

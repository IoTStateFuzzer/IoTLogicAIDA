Java.perform(function(){
  const join_cls=Java.use("cn.com.broadlink.unify.app.family.presenter.FamilyJoinInfoPresenter");
  join_cls.joinFamily.implementation=function(){
    //console.log("join msg=>"+arguments[0]);
    //return this.joinFamily(arguments[0]);
    var con=arguments[0];   //console.log("qrcode data=>"+con);
    let timestamp=new Date().getTime().toString();
    send("save user2|local|GetQrcode_"+timestamp+".json"+" "+con);
    return this.joinFamily(arguments[0]);
  }
});
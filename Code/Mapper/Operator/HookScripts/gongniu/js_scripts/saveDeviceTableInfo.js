Java.perform(function(){
    // save device control obout gongniu plug
    const gongniu_network_module_cls = Java.use("com.gnnetwork.RTNGNNetworkModule");
    let save_obj = {};
    // save_obj["className"] = "com.gnnetwork.GNNetworkAgent";
    let setDeviceProperty_uri = "/v1/dc/setDeviceProperty/";
    gongniu_network_module_cls.request.implementation = function(control_uri, null_str, control_payload, http_method, str_arg5, promise_instance){
        if (control_uri.includes(setDeviceProperty_uri)) {
            console.log("[*] device control");

            save_obj.control_uri = control_uri;
            // save_obj.control_payload = control_payload;
            save_obj.arg4 = str_arg5;
            let timestamp = new Date().getTime().toString();
            send("save user2|remote|DeviceControl_" + timestamp + ".json " + JSON.stringify(save_obj, null, 4));
        } else {
            console.log("[-] Other request");
            // console.log(control_uri);
            // console.log("==========================");
        }
        return this.request.call(this, control_uri, null_str, control_payload, http_method, str_arg5, promise_instance);
    }
});

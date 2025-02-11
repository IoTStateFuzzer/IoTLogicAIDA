var androidDevice = Java.use("android.os.Build").MODEL.value;
console.log("Arguments: " + androidDevice);
console.log(androidDevice.includes("Pixel 7"));

Java.perform(function(){
    function SSLPinning_disable() {
        // ssl pinning
        var arrlist_cls=Java.use("java.util.ArrayList");
        var trusted_manage_cls=Java.use("com.android.org.conscrypt.TrustManagerImpl");
        trusted_manage_cls.checkTrustedRecursive.implementation=function (certs, host, clientAuth, untrustedChain,
            trustAnchorChain, used) {
            let log_cls=Java.use("android.util.Log");
            let throwable_cls=Java.use("java.lang.Throwable");
            let backtrace_str=log_cls.getStackTraceString(throwable_cls.$new());
            return arrlist_cls.$new();
        };
        var pinner_cls = Java.use("okhttp3.CertificatePinner");
        pinner_cls.check.overload("java.lang.String", "java.util.List").implementation=function(a,b){
            return;
        }
        var x509manager_cls=Java.use("javax.net.ssl.X509TrustManager");
        var ssl_context_cls=Java.use("javax.net.ssl.SSLContext");

        var X509TrustManager = Java.registerClass({
            implements: [x509manager_cls],
            methods: {
              checkClientTrusted(chain, authType) { },
              checkServerTrusted(chain, authType) { },
              getAcceptedIssuers() {
                return [];
              },
            },
            name: "com.sensepost.test.TrustManager",
        });
        var TrustManagers = [X509TrustManager.$new()];
        var SSLContextInit=ssl_context_cls.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
        SSLContextInit.implementation=function(keyManager, trustManager, secureRandom){
            SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
        }
    }

    function downgradeEncrypt() {
        // downgrade encrypt on tuya
        try {
            const dbg_cls=Java.use("com.thingclips.smart.android.network.ThingSmartNetWork");
            dbg_cls.mPacketCaptureEnabled.value=true;
        } catch (error) {
            console.log("[!] not tuya, can not find");
        }

        // downgrade rc4 encrypt on mi
        try {
            const release_cls = Java.use("_m_j.hh3");
            const mihome_export_config_cls = Java.use("com.xiaomi.smarthome.application.SHApplication");
            mihome_export_config_cls.exportAppBuildConfig.implementation = function () {
                console.log("[D]called export config cls");
                this.exportAppBuildConfig();
                release_cls.OooO0oO.value = false;
                return;
            }
            const decode_cls = Java.use("com.tencent.mmkv.MMKV");
            decode_cls.decodeBool.overload('java.lang.String', 'boolean').implementation = function () {
                console.log("fucking arg=>" + arguments[0]);
                if (arguments[0] == 'rn_debug_force_plaintext_transmission') {
                    return true;
                }
                return this.decodeBool(arguments[0], arguments[1]);
            }
        } catch (error) {
            console.log("[!] not mi, can not hook _m_j.hh3");
        }
    }

    function downgradeHTTP2() {
        // downgrade http2
        const list_cls=Java.use("java.util.ArrayList");
        const protocol_cls=Java.use("okhttp3.Protocol");
        const builder_cls=Java.use("okhttp3.OkHttpClient$Builder");
        const obj_cls=Java.use("java.lang.Object");
        builder_cls.protocols.implementation=function(){
            var list_obj=list_cls.$new();

            list_obj.add(Java.cast(protocol_cls.HTTP_1_1.value,obj_cls));
            console.log(list_obj);
            return this.protocols(Java.cast(list_obj,Java.use("java.util.List")));
        }
        // eweilian
        builder_cls.$init.overload('okhttp3.OkHttpClient').implementation = function(arg3){
            this.$init(arg3);
            var list_obj=list_cls.$new();
            list_obj.add(Java.cast(protocol_cls.HTTP_1_1.value,obj_cls));
            console.log("[*] Hook builder init(OkHttpClient) to " + list_obj);
            list_obj = Java.cast(list_obj,Java.use("java.util.List"));
            var protocols = this.protocols(list_obj);
        }


        // gongniu
        builder_cls.$init.overload().implementation = function(){
            this.$init();
            var list_obj=list_cls.$new();
            list_obj.add(Java.cast(protocol_cls.HTTP_1_1.value,obj_cls));
            console.log("[*] Hook builder init() to " + list_obj);
            list_obj = Java.cast(list_obj,Java.use("java.util.List"));
            var protocols = this.protocols(list_obj);
        }
        const okhttpclient_cls = Java.use("okhttp3.OkHttpClient");
        okhttpclient_cls.protocols.implementation=function(){
            let ret_value = this.protocols();
            var list_obj=list_cls.$new();
            list_obj.add(ret_value.get(ret_value.size()-1));
            return list_obj
        }
    }

    function tcpPortBanned() {
        try {
            // tuya port banned
            const listen_local_cls=Java.use("com.thingclips.smart.android.device.ThingNetworkInterface");
            listen_local_cls.listenUDP.implementation=function(){
                console.log("avoid user1 to communicate in local channel");
                return;
            }
            const cls1=Java.use("com.thingclips.sdk.hardware.model.GwBroadcastMonitorModel");
            cls1.pdqppqb.overload('android.content.Context').implementation=function(){
                console.log("fucking service over");
                return;
            }
        } catch (error) {
            console.log("[!] not tuya, can not hook");
        }
    }

    downgradeEncrypt();
    SSLPinning_disable();
    downgradeHTTP2();

    if (androidDevice.includes("Pixel 7")) {
        tcpPortBanned();
    }

});

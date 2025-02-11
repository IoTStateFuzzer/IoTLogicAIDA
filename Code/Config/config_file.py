import os
import pwd

# mitm
mitm_path = "/usr/local/python/python3.8/bin/mitmdump"

# wireless card and wi-fi
wireless_card_dict = {
    "local": {
        "ssid": "hostwifi",
        "card": "wlx08beac0deef1"
    },
    "remote": {
        "ssid": "guestwifi",
        "card": "wlx08beac0def1e"
    }
}

# appium
appium_path = f"{pwd.getpwuid(os.getuid()).pw_dir}/.nvm/versions/node/v12.22.12/bin/appium"

# frida server path on android
frida_server_path = '/data/local/tmp/fff'

# system
system_password = "admin"

# abstract string
abstract_str = "Abs_Len"

# some thresholds
threshold_among_each_kind_of_action = 0.50
threshold_in_one_op = 0.79
threshold_of_random = 0.49

#
wait_traffic_time = 2

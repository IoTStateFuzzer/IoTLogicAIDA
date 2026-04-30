from collections import defaultdict, deque

api_key = "xxx"

# Common keywords for operations, can be extended based on actual app features
operation_keywords = {
    "添加设备": "AddDevice",
    "移除设备": "RemoveDevice",
    "分享设备": "SharePlug",
    "共享设备": "SharePlug",
    "接受设备共享": "AcceptDeviceShare",
    "接受分享": "AcceptDeviceShare",
    "取消共享": "UnsharePlug",
    "删除设备": "RemoveDevice",
    "删除": "RemoveDevice",
    "控制设备": "DeviceControl",
    "邀请用户":"InviteToHome",
    "删除用户":"RemoveFromHome",
    "接受邀请":"AcceptInvite"
}

user1_device_config = {
    "platformName": "Android",
    "platformVersion": "13",
    "appPackage": "com.gongniu.smart",
    "appActivity": "com.thebull.init.LaunchActivity",
    "deviceName": "user1_device",
    "udid": "xxx",  # TODO : replace with actual device UDID
    "automationName": "UiAutomator2",
    "newCommandTimeout": 60000,
    "phoneNumber": "xxx",
    "appium:noReset": "true",
    "appium_address": "127.0.0.1",
    "appium_port": 4724,
    "system_port": 8201,
    "user1": defaultdict(lambda: defaultdict(dict)),
    "user2": defaultdict(lambda: defaultdict(dict))
}

user2_device_config = {
    "platformName": "Android",
    "platformVersion": "13",
    "appPackage": "com.gongniu.smart",
    "appActivity": "com.thebull.init.LaunchActivity",
    "deviceName": "user2_device",
    "udid": "xxx",  # TODO : replace with actual device UDID
    "automationName": "UiAutomator2",
    "newCommandTimeout": 60000,
    "phoneNumber": "xxx",
    "appium:noReset": "true",
    "appium_address": "127.0.0.1",
    "appium_port": 4729,
    "system_port": 8201,
    "user1": defaultdict(lambda: defaultdict(dict)),
    "user2": defaultdict(lambda: defaultdict(dict))
}

# ====== config of Tuya ======
tuya_config = {
    "homePage": "",
    "appStartActivity": "",
    "appName": "智能生活",
    "version": "5.6.1",
    "removeDeviceSleepTime": 5,
    "addDeviceSleepTime": 2,
    "resetActions": ["user1|local|RemoveDevice"],
    "overlookActions": [],
    "createDatabaseActionOrder": [],
    "Special": defaultdict(dict)
}

# ====== config of Gongniu ======
gongniu_test=[
    "添加设备:插座 WIFI智能转换器，WIFI名为'Xiaomi 12S pro'，密码为'12345678'。"
]

gongniu_config = {
    "homePage": "",
    "appStartActivity": "",
    "appName": "公牛智家",
    "version": "4.2.1",
    "removeDeviceSleepTime": 5,
    "addDeviceSleepTime": 2,
    "resetActions": ["user1|local|RemoveDevice"],
    "overlookActions": [],
    "createDatabaseActionOrder": [],
    "Special": defaultdict(dict)
}
# multidevice_manager.py
import json
import time
import threading
import copy
import traceback
from typing import List, Dict
from queue import Queue
from collections import defaultdict
from appium.webdriver.common.appiumby import AppiumBy
from scan import gongniu_config, user1_device_config, user2_device_config
from scan import SmartHomeAppScanner
# from zhipuai import ZhipuAI
from langchain_community.chat_models import ChatZhipuAI
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

import os
os.environ["ZHIPUAI_API_KEY"] = "xxx" # TODO: replace with actual API key

class MultiDeviceManager:
    def __init__(self, base_config: dict, device_configs: List[dict]):
        """
        多设备管理核心类（优化版）
        - 自动从设备配置读取phoneNumber
        - 大模型动态决策数据传递
        - 新增：Agent框架支持
        """
        # self.api_key = api_key
        self.devices = {}  # phoneNumber -> SmartHomeAppScanner
        self.shared_data = defaultdict(dict)
        self.task_queue = Queue()
        self._init_devices(base_config, device_configs)
        self._running = False
        self.llm_client = ChatZhipuAI(model="glm-4-flash", temperature=0.7, top_p=0.9, max_tokens=5000)
        
        self.action_feedback = defaultdict(list)
        self.execution_context = {}

    def _init_devices(self, base_config, device_configs):
        """init devices based on provided configurations (optimized)"""

        for config in device_configs:
            device_conf = copy.deepcopy(config)
            app_conf = copy.deepcopy(base_config)

            # confirm phoneNumber exists in device configuration
            if "phoneNumber" not in device_conf:
                raise ValueError("device configuration must include 'phoneNumber' key")

            # create scanner instance for the device
            scanner = SmartHomeAppScanner(
                # api_key=self.api_key,
                APP_json_config=app_conf,
                device_config=device_conf
            )

            # key by phoneNumber for easy reference in tasks
            phone = device_conf["phoneNumber"]
            self.devices[phone] = scanner
            scanner.multi_device_manager = self

    def generate_multi_tasks(self):
        """generate multi-device collaborative tasks using LLM (optimized)"""
        
        prompt = f"""作为物联网测试专家，请生成需要以下设备协同的测试用例。现有设备：
        {', '.join(self.devices.keys())}

        要求：
        1. 必须使用上述手机号作为设备标识
        2. 包含设备共享等需要数据传递的场景
        3. 返回JSON格式：{{"tasks": [{{"name":"测试名称","steps":[{{"device":"手机号","operation":"操作指令"}}]}}]}}"""

        try:
            response = self.llm_client.invoke([prompt, HumanMessage("请生成物联网控制APP的完整设备协同测试用例列表")])
            return self._parse_task_response(response)
        except Exception as e:
            print(f"generate_multi_tasks failed: {str(e)}")
            traceback.print_exc()
            return []

    def _parse_task_response(self, response: AIMessage) -> List[dict]:
        """解析任务并验证设备存在性"""
        try:
            task_data = json.loads(response.content[response.content.find('{'):response.content.rfind('}') + 1])
            valid_tasks = []

            for task in task_data.get("tasks", []):
                valid_steps = []
                for step in task.get("steps", []):
                    if step.get("device") in self.devices:
                        valid_steps.append(step)
                    else:
                        print(f"Invalid device: {step.get('device')}")

                if valid_steps:
                    task["steps"] = valid_steps
                    valid_tasks.append(task)

            return valid_tasks
        except Exception as e:
            print(f"generate_multi_tasks failed: {str(e)}")
            return []

    def execute_task(self, task: dict):
        """执行任务（智能数据传输决策版）"""
        print(f"\n🔧 Mission start: {task['name']}")
        task_status = True
        step_context = {}
        
        self.execution_context = {
            "task_name": task['name'],
            "start_time": time.time(),
            "steps_completed": 0,
            "device_states": {}
        }

        for step_idx, step in enumerate(task["steps"]):
            device = self.devices[step["device"]]
            operation = step["operation"]

            step_context.update({
                "current_operation": operation,
                "step_index": step_idx,
                "source_device": device.json_config["phoneNumber"],
                "previous_steps": self.execution_context.get("steps_completed", 0)
            })

            print(f"📱 {step['device']} 执行: {operation}")
            
            device.execution_feedback = self.action_feedback.get(device.json_config["deviceName"], [])
            
            success = device.execute_user_operation(operation)

            if success:
                self._smart_data_transfer(device, step_context)
                
                # 记录成功
                self.action_feedback[device.json_config["deviceName"]].append({
                    "action": operation,
                    "success": True,
                    "timestamp": time.time(),
                    "reason": "操作成功完成"
                })
                
                self.execution_context["steps_completed"] += 1
                self.execution_context["device_states"][device.json_config["phoneNumber"]] = device._get_state_signature()

            # 失败处理
            if not success:
                # 记录失败
                self.action_feedback[device.json_config["deviceName"]].append({
                    "action": operation,
                    "success": False,
                    "timestamp": time.time(),
                    "reason": "操作未能完成"
                })
                task_status = False
                break

        # 后置处理
        if task_status:
            print(f"✅ Mission completed: {task['name']}")
            return True
        else:
            print(f"❌ Mission failed: {task['name']}")
            self._reset_devices()
            return False

    def _smart_data_transfer(self, device, context: dict):
        """基于大模型的智能数据传输决策"""
        context["feedback_history"] = self.action_feedback.get(device.json_config["deviceName"], [])
        decision = self._get_data_transfer_decision(device, context)

        if decision["need_transfer"]:
            print(f"📤 需要数据传输: {decision['reason']}")
            self._capture_data_by_decision(device, decision)
            
            # 新增：记录数据传输结果作为反馈
            self.action_feedback[device.json_config["deviceName"]].append({
                "action": "data_transfer",
                "key": decision.get("storage_key", ""),
                "success": True,
                "timestamp": time.time()
            })
        else:
            print(f"⏩ 跳过数据传输: {decision['reason']}")

    def _get_data_transfer_decision(self, device, context: dict) -> dict:
        """获取大模型的数据传输决策（增强版-包含反馈）"""
        prompt = SystemMessage(content=f"""作为自动化测试专家，请分析当前操作是否需要跨设备数据传输：

        上下文信息：
        - 当前操作：{context['current_operation']}
        - 操作设备：{context['source_device']}
        - 页面状态：{device._get_state_signature()[:50]}...
        
        历史操作反馈：
        {self._format_feedback_history(context.get('feedback_history', []))}

        请考虑以下情况：
        1. 是否需要显式传递数据（如邀请码、分享链接）
        2. 接收方是否能自主获取数据（如消息通知）
        3. 是否需要等待特定状态变化
        4. 参考历史反馈，判断类似操作是否成功过

        返回JSON格式：
        {{
            "need_transfer": boolean,
            "reason": "决策理由",
            "data_type": ["text"/"clipboard"/"none"],
            "element_xpath": "可选元素路径",
            "storage_key": "数据存储键名"
        }}""")

        # 获取当前页面元素上下文
        elements = device._get_interactable_elements()
        element_context = HumanMessage(content=device._build_element_context(elements))

        # 调用大模型决策
        try:
            response = self.llm_client.invoke([prompt, element_context])

            decision = device._parse_llm_response(response)
            return self._validate_decision(decision)
        except Exception as e:
            print(f"数据传输决策失败: {str(e)}")
            return {
                "need_transfer": False,
                "reason": "决策失败，默认不传输",
                "data_type": "none"
            }
            
    def _format_feedback_history(self, feedback_history: list) -> str:
        """格式化反馈历史为提示词可用格式"""
        if not feedback_history:
            return "无历史操作反馈"
            
        formatted = []
        for i, item in enumerate(feedback_history[-5:], 1):  # 只取最近5条
            status = "成功" if item.get("success", False) else "失败"
            formatted.append(f"{i}. 操作'{item.get('action', '未知')}' - {status} - {item.get('reason', '无原因')}")
            
        return "\n".join(formatted)

    def _validate_decision(self, decision: dict) -> dict:
        """验证大模型决策有效性"""
        valid_decision = {
            "need_transfer": bool(decision.get("need_transfer", False)),
            "reason": str(decision.get("reason", "")),
            "data_type": decision.get("data_type", "none"),
            "element_xpath": str(decision.get("element_xpath", "")),
            "storage_key": str(decision.get("storage_key", ""))
        }

        if valid_decision["need_transfer"] and not valid_decision["storage_key"]:
            valid_decision["storage_key"] = f"auto_key_{int(time.time())}"

        return valid_decision

    def _capture_data_by_decision(self, device, decision: dict):
        """执行数据采集存储"""
        if decision["data_type"] == "text":
            self._capture_text_data(device, decision)
        elif decision["data_type"] == "clipboard":
            self._capture_clipboard_data(device, decision)

    def _capture_text_data(self, device, decision: dict):
        """采集文本类型数据"""
        try:
            element = device.find_element_with_scroll(decision["element_xpath"])
            if element and element.text:
                self.shared_data[decision["storage_key"]] = {
                    "value": element.text,
                    "source": device.json_config["phoneNumber"],
                    "timestamp": time.time(),
                    "xpath": decision["element_xpath"]
                }
                print(f"✅ 文本数据已存储: {decision['storage_key']}")
            else:
                print(f"⚠️ 文本数据采集失败: {element is None}")
        except Exception as e:
            print(f"文本数据采集异常: {str(e)}")

    def _capture_clipboard_data(self, device, decision: dict):
        """collect clipboard data"""
        try:
            clipboard_data = device.driver.get_clipboard_text()
            if clipboard_data:
                self.shared_data[decision["storage_key"]] = {
                    "value": clipboard_data,
                    "source": device.json_config["phoneNumber"],
                    "timestamp": time.time(),
                    "type": "clipboard"
                }
                print(f"✅ 剪贴板数据已存储: {decision['storage_key']}")
            else:
                print("⚠️ 剪贴板为空")
        except Exception as e:
            print(f"剪贴板访问失败: {str(e)}")

    def start_automation(self):
        """start automation process"""
        self._running = True
        tasks = self.generate_multi_tasks()

        print(f"📋 total tasks: {len(tasks)}")
        print(f"{tasks}")
        print("🚀 starting automation...")
        for task in tasks:
            if not self._running:
                break
            self.execute_task(task)

        self._running = False

    def _reset_devices(self):
        """reset devices to homepage and clear context"""
        for device in self.devices.values():
            device._reset_to_homepage()
            device.operation_flow = []
            device.excluded_xpaths = []


# 示例使用
if __name__ == "__main__":

    manager = MultiDeviceManager(
        base_config=gongniu_config,
        device_configs=[user1_device_config, user2_device_config]
    )

    # manager.start_automation()

    # example task for testing
    simpleple_task ={'name': '邀请其他成员进入家庭', 'steps': [{'device': 'xxx', 'operation': '通过"我的家"添加家庭成员"xxx"'},
                                       {'device': 'xxx', 'operation': '通过消息列表同意被用户"xxx"添加为家庭成员'}]}

    manager.execute_task(simpleple_task)
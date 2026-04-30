import difflib
import json
import os
import time
import copy
import traceback
from typing import List, Dict
import requests
from selenium.webdriver import ActionChains
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.actions import interaction
from selenium.webdriver.common.actions.action_builder import ActionBuilder
from selenium.webdriver.common.actions.pointer_input import PointerInput
from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from selenium.common import NoSuchElementException, WebDriverException, StaleElementReferenceException
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from collections import defaultdict, deque
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.actions import interaction
from selenium.webdriver.common.actions.action_builder import ActionBuilder
from selenium.webdriver.common.actions.pointer_input import PointerInput
from appium.options.android import UiAutomator2Options
import subprocess
import socket
from Logger import mlog
from langchain_community.chat_models import ChatZhipuAI
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
import threading
from config import *
import re
from openai import OpenAI

os.environ["ZHIPUAI_API_KEY"] = "xxx"

class SmartHomeAppScanner:
    def __init__(self, APP_json_config: dict, device_config: dict, explore_horizontal=True, save_path="gongniu_test"):
        self.driver = None
        self.json_config = APP_json_config
        self.json_config["deviceName"] = device_config["deviceName"]
        self.json_config["phoneNumber"] = device_config["phoneNumber"]
        self.json_config["device_id"] = device_config["udid"]  # Add the unique device identifier.
        self.json_config["phoneNumber"] = device_config["phoneNumber"]  # Add the unique device identifier.
        self.save_path = save_path
        
        # Create the required directory structure.
        self._ensure_directories_exist()
        
        # Ensure the config contains the required structure.
        if "createDatabaseActionOrder" not in self.json_config:
            self.json_config["createDatabaseActionOrder"] = []
            
        # Ensure the user config structure exists.
        for user in ["user1", "user2"]:
            if user not in self.json_config:
                self.json_config[user] = {"local": {}, "remote": {}}
            else:
                for scope in ["local", "remote"]:
                    if scope not in self.json_config[user]:
                        self.json_config[user][scope] = {}
        
        # Ensure the Special config exists.
        if "Special" not in self.json_config:
            self.json_config["Special"] = {}
        
        self.appium_process = None  # Appium process handle.
        self.UDID = device_config["udid"]

        self._start_appium_server(address=device_config["appium_address"], port=device_config["appium_port"])

        self.state_history = deque(maxlen=10)  # State history.
        self.sign_state_history = []  # State signature history.
        self.page_structure_history = []  # Page structure signature history for loop detection.
        self.current_flow = []
        self.visited_states = set()
        self._init_appium_driver(device_config=device_config)
        self.operation_flow = []  # Operation flow records.
        self.max_steps = 20  # Maximum operation steps to prevent infinite loops.
        self.llm_client = ChatZhipuAI(model="glm-4-plus", temperature=0.1, top_p=0.7, max_tokens=1000)
        self.openai_client =  OpenAI(api_key="sk-iTYontZuQszR4Fha4neyh1t7rhZuyAF1t7v847JOmQJJlip4", base_url="https://yunwu.ai/v1")
        
        self._init_prompt_template()  # Initialize the prompt template.
        self.excluded_xpaths = []
        # Swipe-related parameters.
        self.swipe_history = set()  # Record swiped directions.
        self.max_swipe_attempts = 1  # Maximum swipe attempts.
        self.collected_elements_xpath = set()  # Collected element XPath values.
        self.collected_elements = set()

        # Test task generation state.
        self.test_cases = []
        self._init_testcase_prompt()  # Initialize the test case generation prompt.

        # Agent-related state.
        self.execution_feedback = []  # Operation feedback history.
        self.action_results = {}  # Recent operation result cache.
        self.observation_cache = {}  # Observation cache.
        self.reflection_history = []  # Reflection history.
        
        # Error-decision recovery state.
        self.similar_threshold = 0.9  # Initial page similarity threshold.
        self.threshold_adjustment_history = []  # Threshold adjustment history.
        self.page_similarity_samples = []  # Page similarity samples.
        
        # Page exploration state tracking.
        self.current_page_signature = None  # Current page signature.
        self.is_current_page_explored = False  # Whether the current page has been explored.
        
        with open("page_signatures.txt", "w", encoding="utf-8") as f:
            pass  # Clear file contents.
        with open("Loop_page_signatures.txt", "w", encoding="utf-8") as f:
            pass  # Clear file contents.

        self.explore_horizontal = explore_horizontal

        # Ensure page exploration state variables are initialized.
        if not hasattr(self, 'current_page_signature'):
            self.current_page_signature = None
        if not hasattr(self, 'is_current_page_explored'):
            self.is_current_page_explored = False

    def _start_appium_server(self, address: str, port: int):
        """Start the Appium service."""
        try:
            if self._is_port_in_use(port):
                print(f"Port {port} is already in use and is already killed")
            # start appium -a 127.0.0.1 -p 4723 --relaxed-security --allow-cors --base-path /wd/hub
            # Start the Appium service with logging.
            # self.appium_process = subprocess.Popen(
            #     ["D:\\nodejs\\node_global\\appium",
            #      "-p", str(port),
            #      "--address", address,
            #      "--log-timestamp",
            #      "--relaxed-security",
            #      "--session-override",
            #      "--local-timezone",
            #      "--log", f"appium_{port}.log"],
            #     stdout=subprocess.PIPE,
            #     stderr=subprocess.STDOUT,
            #     shell=True,
            #     universal_newlines=True
            # )
            # Build the startup command.
            appium_cmd = (f"start appium -a {address} -p {str(port)} --relaxed-security --log-timestamp "
                          f"--session-override --local-timezone --log appium_{port}.log --allow-cors --base-path /wd/hub")

            # Start Appium.
            self.appium_process = subprocess.Popen(
                appium_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                universal_newlines=True
            )

            # Wait for the service to become ready.
            # if not self._wait_for_appium_ready(port):
            #     raise RuntimeError("Appium server failed to start within timeout")

            print(f"✅ Appium server started on port {port}")

        except Exception as e:
            print(f"❌ Failed to start Appium: {str(e)}")
            self._stop_appium_server()
            raise

    def _is_port_in_use(self, port: int) -> bool:
        """Check whether the port is in use and kill the owning process if needed."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Check whether the port is in use.
            if s.connect_ex(('localhost', port)) == 0:
                # The port is in use. Kill the process that owns it.
                self._kill_process_using_port(port)
                return True  # The port was in use and has been handled.
            return False  # The port is not in use.

    def _kill_process_using_port(self, port: int):
        """Kill the process that is using the specified port."""
        try:
            # Find the process ID using the port.
            result = subprocess.run(
                ["netstat", "-ano", "|", "findstr", f":{port}"],
                shell=True,
                capture_output=True,
                text=True
            )
            output = result.stdout.strip()

            if not output:
                print(f"Port {port} is not in use. No process needs to be killed.")
                return

            # Extract process IDs.
            pids = set()
            for line in output.splitlines():
                parts = line.split()
                # Ensure the TCP row and port were parsed.
                if len(parts) > 4 and parts[1].endswith(f":{port}") and parts[3] == "LISTENING":
                    pids.add(parts[4])

            # Kill the processes.
            for pid in pids:
                os.system(f"taskkill /PID {pid} /F")
                print(f"Killed process {pid} that was using port {port}.")

        except Exception as e:
            print(f"Error while trying to kill the process using port {port}: {e}")

    def _wait_for_appium_ready(self, port: int, timeout=30) -> bool:
        """Wait for the Appium service to become ready."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"http://localhost:{port}/wd/hub/session", timeout=5)
                if response.status_code == 200:
                    print(f"http://localhost:{port}/wd/hub/session is ready.")
                    return True
            except requests.ConnectionError:
                time.sleep(1)
        return False

    def _stop_appium_server(self):
        """Stop the Appium service."""
        if self.appium_process:
            try:
                self.appium_process.terminate()
                self.appium_process.wait(timeout=10)
                print("🛑 Appium server stopped")
            except subprocess.TimeoutExpired:
                self.appium_process.kill()
            finally:
                self.appium_process = None

    def __del__(self):
        """Stop services automatically during cleanup."""
        try:
            # Try to close the driver first.
            if hasattr(self, 'driver') and self.driver:
                try:
                    self.driver.quit()
                    print("WebDriver has been closed")
                except Exception as e:
                    print(f"Error while closing WebDriver: {e}")
                finally:
                    self.driver = None
            
            # Then stop the Appium service.
            self._stop_appium_server()
        except Exception as e:
            print(f"Error while cleaning up resources: {e}")

    def _init_appium_driver(self, device_config: dict):
        # Appium configuration.
        desired_caps = copy.deepcopy(device_config)

        # Check whether the port is in use, and try to clean it up if needed.
        port = device_config["appium_port"]
        a='''
        if self._is_port_in_use(port):
            print(f"port {port} has been occupied, trying to clean up...")
            self._kill_process_using_port(port)
            # wait for a few seconds to ensure the port is released.
            for _ in range(5):
                if not self._is_port_in_use(port):
                    print(f"port {port} has been released successfully")
                    break
                time.sleep(1)
            else:
                raise RuntimeError(f"cannot start Appium because port {port} is still in use after cleanup attempts")
        '''
        # Ensure any previous driver has been closed.
        if hasattr(self, 'driver') and self.driver:
            try:
                self.driver.quit()
            except Exception as e:
                print(f"Error while closing the previous driver instance: {e}")
            finally:
                self.driver = None

        try:
            options = UiAutomator2Options().load_capabilities(desired_caps)
            options.platformName = desired_caps["platformName"]
            options.deviceName = desired_caps["deviceName"]
            self.driver = webdriver.Remote(
                f'http://{device_config["appium_address"]}:{device_config["appium_port"]}/wd/hub', options=options)
            self.json_config["appStartActivity"] = self.driver.current_activity
            self._wait_for_homepage()
        except WebDriverException as e:
            print(f"Appium connection failed: {str(e)}")
            # Record more detailed error information.
            if "connection refused" in str(e).lower() or "10061" in str(e):
                print("Connection refused. The Appium server may not be running, or the port may be occupied.")
                if not self._wait_for_appium_ready(port, timeout=5):
                    print(f"Appium server is not ready on port {port}")
            raise
        except ImportError:
            print("Please install the latest Appium client: pip install --upgrade appium-python-client")
            raise
        except Exception as e:
            print(f"Unknown error while initializing the Appium driver: {type(e).__name__} - {str(e)}")
            raise

    def _init_testcase_prompt(self):
        """Initialize the test case generation prompt."""
        self.testcase_prompt = """As a senior QA engineer, generate complete test cases for a smart home app. Known features:
        1. Device management: add/delete lights, plugs, and other devices
        2. Device control: power switch, brightness adjustment, timers, and similar controls
        3. Scene modes: create/execute scenes, such as home mode and sleep mode
        4. Device sharing: share devices with other users
        5. System settings: notification management, firmware upgrade, and related settings

        Generate according to the following rules:
        1. Cover all feature modules
        2. Include positive and negative test cases
        3. Test case format: "operation [test data]", for example: "Add T02 low-voltage light strip"
        4. Return a JSON array: {"test_cases": [{"operation":"test operation 1","reason": "brief test reason"}, {"operation":"test operation 2","reason": "brief test reason"}, ...]}"""

    def generate_test_cases(self) -> List[str]:
        """Use the LLM to generate complete test cases."""
        try:
            chat = ChatZhipuAI(model="glm-4-plus", temperature=0.7, top_p=0.9, max_tokens=10000)
            response = chat.invoke([
                SystemMessage(content=self.testcase_prompt),
                HumanMessage(content="Generate a complete test case list for an IoT control app.")
            ])
            result = self._parse_llm_response(response)
            if isinstance(result.get("test_cases", []), list):
                print("'test_cases' was generated as a list")
                self.test_cases = result.get("test_cases", [])
            else:
                self.test_cases = json.loads(result.get("test_cases", []))
                print("'test_cases' was not generated as a list")
            return self.test_cases
        except Exception as e:
            print(f"Test case generation failed: {str(e)}")
            traceback.print_exc()
            return []

    def full_automation(self):
        """Fully automated test flow."""
        if not self.test_cases:
            self.generate_test_cases()
        print(f"Generated {len(self.test_cases)} test cases")
        for case in self.test_cases:
            print(f"\nExecuting test case: {case}")
            if self.execute_user_operation(case):
                self._save_config(self.save_path)
                print(f"Test case {case} executed successfully")
            else:
                print(f"Test case {case} failed")
            self._reset_to_homepage()

    def _explore_full_page(self):
        """Explore the page with smart swiping while avoiding recursive calls."""
        print(f"⭐ Starting full page exploration...")
        if self.explore_horizontal:
            directions = ['down', 'up', 'left', 'right']  # Include horizontal directions.
        else:
            directions = ['down', 'up']  # Only include vertical directions.
        
        last_element_count = len(self.collected_elements_xpath)
        retry = 0
        exploring = True  # Exploration state flag.
        swap_count = {'down': 0, 'up': 0, 'left': 0, 'right': 0}
        elements = set()
        
        # Temporarily disable exploration in _get_interactable_elements.
        original_max_swipe = self.max_swipe_attempts
        for el in self._base_get_elements():
            elements.add(el)
            try:
                info = self._capture_element_info(el)
                xpath = info['generated_xpath']
                if xpath not in self.collected_elements_xpath:
                    print(f"Collected new element: {xpath}")
                    self.collected_elements_xpath.add(xpath)
                    self.collected_elements.add(el)
                if "edittext" in info['class'].lower() and info["focused"] == "true":
                    print("Preparing to enter text, so page exploration is skipped")
                    self.max_swipe_attempts = 0  # Disable automatic exploration.
            except StaleElementReferenceException:
                continue

        # self.max_swipe_attempts = 0  # Disable automatic exploration.

        try:
            while retry < self.max_swipe_attempts and exploring:
                # Swipe once in every direction.
                for direction in directions:
                    original_state = self._get_state_signature()
                    self._swipe_screen(direction, exploring=True)
                    swap_count[direction] += 1
                    while self._get_state_signature() != original_state:
                        original_state = self._get_state_signature()
                        self._swipe_screen(direction, exploring=True)
                        swap_count[direction] += 1
                        
                    # Restore the page position.
                    for count_slip in range(swap_count[direction]):
                        if direction == 'down':
                            self._swipe_screen('up', exploring=True)
                        elif direction == 'up':
                            self._swipe_screen('down', exploring=True)
                        elif direction == 'left':
                            self._swipe_screen('right', exploring=True)
                        elif direction == 'right':
                            self._swipe_screen('left', exploring=True)
                swap_count = {'down': 0, 'up': 0, 'left': 0, 'right': 0}

                # Check whether the element count increased.
                if len(self.collected_elements_xpath) == last_element_count:
                    retry += 1
                    print(f"⭐ No new elements found in this round, retry={retry}")
                else:
                    retry = 0  # Reset the counter after finding new elements.
                    print(f"⭐ Found new elements in this round. Total elements: {len(self.collected_elements_xpath)}")

                last_element_count = len(self.collected_elements_xpath)

                # Stop after two consecutive rounds with no new elements or after reaching the max attempts.
                if retry >= 2 or len(self.collected_elements_xpath) >= 100:
                    exploring = False
                    print(f"⭐ Page exploration finished. Stop condition met: retry={retry}, element count={len(self.collected_elements_xpath)}")
        finally:
            self.max_swipe_attempts = original_max_swipe  # Restore the original setting.
            print(f"⭐ Page exploration fully completed. Collected {len(self.collected_elements_xpath)} elements")
            
            # Get the current page signature and mark it as explored.
            current_signature = self._get_state_signature()
            if self.current_page_signature != current_signature:
                print(f"⚠️ Page signature changed during exploration. Updating signature")
                self.current_page_signature = current_signature
            self.is_current_page_explored = True

    def _swipe_screen(self, direction: str, exploring=False):
        """Improved smart swipe method with an exploration-mode flag."""
        window_size = self.driver.get_window_size()
        start_x = window_size['width'] / 2
        start_y = window_size['height'] / 2
        elements = set()

        swipe_params = {
            'up': {'end_x': start_x, 'end_y': start_y * 0.2},
            'down': {'end_x': start_x, 'end_y': start_y * 1.8},
            'left': {'end_x': window_size['width'] * 0.2, 'end_y': start_y},
            'right': {'end_x': window_size['width'] * 0.8, 'end_y': start_y}
        }

        if direction not in swipe_params:
            return

        # Perform the swipe.
        self.driver.swipe(
            start_x, start_y,
            swipe_params[direction]['end_x'],
            swipe_params[direction]['end_y'],
            500
        )
        time.sleep(1)  # Wait for the page to stabilize.

        # Collect elements only in exploration mode to avoid recursive calls.
        if exploring:
            for el in self._base_get_elements():
                elements.add(el)
            # elements.add(self._base_get_elements())  # Call the base method directly.
            print(f"Swiped {direction}. Element count: {len(elements)}")
            for el in elements:
                try:
                    info = self._capture_element_info(el)
                    xpath = info['generated_xpath']
                    if xpath not in self.collected_elements_xpath:
                        print(f"Collected new element: {xpath}")
                        self.collected_elements_xpath.add(xpath)
                        self.collected_elements.add(el)
                except StaleElementReferenceException:
                    continue

    def _get_interactable_elements(self):
        """Refactored element retrieval method."""
        # Remove the internal _explore_full_page call.
        # return self._filter_elements(
        #     [self.driver.find_element(AppiumBy.XPATH, xpath)
        #      for xpath in self.collected_elements_xpath]
        # )

        return self._filter_elements(
            [self.find_element_with_scroll(xpath, max_swipe=5)
             for xpath in self.collected_elements_xpath]
        )

    def _filter_elements(self, elements):
        """Filter interactable elements with additional safeguards."""
        filtered_elements = []
        
        # Get XPath values for known bad elements.
        error_xpaths = []
        
        # Collect bad element XPath values from execution feedback.
        for item in self.execution_feedback:
            if item.get("action") == "avoided_bad_element" and "xpath" in item:
                error_xpaths.append(item["xpath"])
                
        # Collect bad element XPath values from error-decision evaluations.
        error_feedbacks = [fb for fb in self.execution_feedback if fb.get("action") == "decision_error_evaluation"]
        for item in error_feedbacks:
            error_details = item.get("error_details", {})
            prev_decision = error_details.get("previous_decision", {})
            if "xpath" in prev_decision:
                error_xpaths.append(prev_decision["xpath"])
        
        # Filter elements.
        for element in elements:
            # Exclude invisible elements.
            if not self._is_element_visible(element):
                continue
                
            # Exclude element types that should not be used.
            if self._is_element_excluded(element):
                continue
                
            # Get the element XPath.
            try:
                element_xpath = element.get_attribute("xpath")
                
                # Exclude known bad element XPath values.
                if element_xpath in error_xpaths:
                    print(f"⚠️ Excluding known bad element: {element_xpath}")
                    continue
                    
                filtered_elements.append(element)
            except Exception:
                # If XPath cannot be retrieved, still keep the element in the filtered list.
                filtered_elements.append(element)
        
        return filtered_elements

    def _is_element_visible(self, element):
        """Enhanced visibility validation."""
        try:
            elem_location = element.location
            elem_size = element.size
            screen = self.driver.get_window_size()

            # Calculate the element bottom position.
            elem_bottom = elem_location['y'] + elem_size['height']
            screen_bottom = screen['height'] * 1  # Reserve a 5% bottom boundary.
            a = elem_location['y'] >= 0 and elem_bottom <= screen_bottom
            return elem_location['y'] >= 0 and elem_bottom <= screen_bottom
        except StaleElementReferenceException:
            return False

    def _is_element_excluded(self, element):
        """Check whether an element should be excluded."""
        try:
            xpath = self._generate_xpath({}, element)
            # Do not fully exclude clicked elements anymore; only record state.
            return False
        except:
            return False

    def _base_get_elements(self):
        """Original element retrieval logic."""
        elements = self.driver.find_elements(
            AppiumBy.XPATH,
            '//*[@clickable="true" or @longClickable="true"]|//android.widget.Button[@clickable="false"]'
        )
        return elements if elements else self.driver.find_elements(
            AppiumBy.XPATH,
            '//*[@enabled="true"]'
        )

    def _init_prompt_template(self):
        """Initialize the enhanced LLM prompt template for the agent architecture."""
        pass

    def _get_llm_decision(self, operation_type: str, operation_detail: str, elements: list) -> dict:
        """
        Call the LLM for decision making with multi-threaded prediction and voting.
        
        Args:
            operation_type: Operation type, such as "添加设备".
            elements: Page element list.
            
        Returns:
            dict: Decision result.
        """
        element_info_str = self._build_element_context(elements)
        
        # Get text information from non-interactable controls.
        non_interactable_text = self._get_non_interactable_text_elements()
        non_interactable_element_prompts = f"""
        The following text comes from non-interactable page elements. Use it to understand the page content and context:
        {non_interactable_text}
        """
        # Combine interactable elements with non-interactable text context.
        element_prompts = f"""
        From the elements below, choose the most likely next element to operate on according to the rules, or decide whether to enter a wait state. Use default handling for information not specified in the user goal. Do not operate outside the element scope below:
        {element_info_str}
        """

        try:
            messages = []
            
            # Add operation history, keeping the latest five records.
            if self.state_history:
                history_content = "Recent operation history:\n" + "\n".join(
                    [f"{i + 1}. {h}" for i, h in enumerate(list(self.state_history)[-5:])]
                )
                
            
            # Add operation feedback history.
            if self.execution_feedback:
                feedback_content = self._format_action_feedback(self.execution_feedback)
                
                
            # Add reflection records.
            if self.reflection_history:
                reflection_content = self._format_reflections()
                
            
            # Add error-decision experience feedback.
            error_feedbacks = [fb for fb in self.execution_feedback if fb.get("action") == "decision_error_evaluation"]
            if error_feedbacks:
                error_content = self._format_decision_errors(error_feedbacks)
                
            
            # Generate the system prompt content through string interpolation.
            system_prompt_content = f"""You are a professional app operation-flow analysis assistant using an Observe-Think-Act-Feedback agent architecture. The current logged-in app user is {self.json_config["deviceName"]}, and the current user's phone number is {self.json_config["phoneNumber"]}. Make a decision based on the following information:

    [Observation]
    1. User goal: {operation_type}-{operation_detail}
    2. Current page element list. Elements marked with ★ are interactable.
    3. Current non-interactable page text, which helps understand page content and context.
    4. Operation history.
    5. Historical operation feedback.

    [Thinking Rules]
    1. Analyze the gap between the goal and the current state.
    2. Consider historical operation feedback and avoid repeatedly failed paths.
    3. Predict possible operation results.
    4. Use child-control text and non-interactable text to understand the current page context and state.
    5. Form a clear action plan.
    6. Use default handling for information not specified in the user goal.

    [Interaction Priority Rules]
    1. First priority: interactable elements marked with ★ where clickable/long-clickable is true, and Button elements. Sometimes a button may not appear clickable but can still be tried.
    2. Second priority: other enabled elements where enabled is true.
    3. Third priority: operation paths with high historical success rates.
    4. Important: elements marked with ⚠️ are known to cause errors. Never choose these elements.

    [Element Selection Rules]
    1. Among similar elements, choose the text description that best matches the user goal.
    2. Among interactable elements, prefer elements directly related to the target, such as UI text containing '添加', '创建', or '控制'.
    3. If flow-forward elements such as '下一步' or '确定' exist, prefer them.
    4. Avoid elements that have already been operated on and caused failure.
    5. Use default handling for information not specified in the user goal.
    6. Review error-decision experience to avoid repeating similar mistakes.
    7. Important: use non-interactable text to understand the current page content and context.
    8. Key rule: regardless of other conditions, never choose elements marked with ⚠️.
    
    [Wait-State Rules]
    1. Consider entering a wait state when any of the following is detected:
       - The page shows prompts such as connecting device, network setup, or pairing.
       - The page has a progress bar, loading animation, or similar indicator.
       - The previous click was on actions such as "连接", "添加", or "配对", which may take time.
       - The page indicates waiting or processing.
    2. In wait state, the page is checked every 6 seconds without extra operations.
    3. If the page does not change for a long time, such as more than 30 seconds, another operation may be needed.
    4. If a previous wait operation timed out without page changes within 30 seconds, avoid choosing wait again. Choose an interactable control instead to advance the flow.

    [Output Requirements]
    1. Strictly follow the interaction priority rules. Element actions may only be "click", "long-click", or "text_input".
    2. If an element operation is needed, return: {{"reason": "selection reason", "xpath": "element xpath", "action_type": "element action type", "input_text": "text to enter when action_type is text_input", "expected_outcome": "expected result after this operation"}}
    3. If a wait state is needed, return: {{"action_type": "wait", "reason": "reason for entering wait state", "wait_time": optional estimated wait time in seconds, default 30, "expected_outcome": "expected result after waiting"}}
    4. If the goal is complete and the full execution logic has finished, return: {{"status": "complete", "reason": "completion reason"}}
    5. Return only one operation."""
            #messages.append(system_prompt_content)
            if self.state_history:
                messages.append(history_content)
            if self.execution_feedback:
                messages.append(feedback_content)
            if self.reflection_history:
                messages.append(reflection_content)
            if error_feedbacks:
                messages.append(error_content)
            messages.append(non_interactable_element_prompts)
            messages.append(element_prompts)
            # Page element information.
            
            #messages.append("""[Output Requirements]
    #1. Strictly follow interaction priority rules. Element actions may only be "click", "long-click", or "text_input". Wait state is also allowed.
    #2. If an element operation is needed, return: {{"reason": "selection reason", "xpath": "element xpath", "action_type": "element action type", "input_text": "text to enter when action_type is text_input", "expected_outcome": "expected result after this operation"}}
    #3. If a wait state is needed, return: {{"action_type": "wait", "reason": "reason for entering wait state", "wait_time": optional estimated wait time in seconds, default 30, "expected_outcome": "expected result after waiting"}}
    #4. If the goal is complete, return: {{"status": "complete", "reason": "completion reason"}}""")
            
            print(f"messages: {messages}\n")

            # Use multiple threads to predict candidate elements.
            predictions = self._multi_thread_predict(messages, element_prompts, system_prompt_content)
            
            # Collect prediction results and vote.
            prediction_results = self._collect_predictions(predictions)
            vote_result = prediction_results["vote_result"]
            wait_votes = prediction_results["wait_votes"]
            total_threads = prediction_results["total_threads"]
            wait_threshold_met = prediction_results["wait_threshold_met"]

            vote_messages = "\n".join(messages) + f"Branch-thread voting has completed. Make the final decision based on the highest aggregate vote score and your own judgment. Sometimes the same element may produce different XPath values because of punctuation differences, so distinguish carefully.\n\n" \
            +f"Branch-thread element voting result: {vote_result}\n" \
            +f"Wait-state votes: {wait_votes}/{total_threads}\n" \
            +f"Wait threshold reached (requires 3 votes): {'Yes' if wait_threshold_met else 'No'}\n\n" \
            +"Wait state may only be considered when the vote count is at least 3. If this condition is not met, choose the highest-voted element for operation."
            print(vote_messages)
            response = self.openai_client.chat.completions.create(
                model="deepseek-reasoner",  # The yunwu-gpt4 name was only a local alias; gpt-4 is sufficient in practice.
                messages=[
                    {"role": "system", "content": system_prompt_content},
                    {"role": "user", "content": vote_messages}
                ],
                stream=False,
                temperature=0.2
            )
            # Pass voting results to the main model for the final decision.
            #messages.append(HumanMessage(content=))
            
            #chat = ChatZhipuAI(model="glm-4-plus", temperature=0.1, top_p=0.7, max_tokens=1000)
            #response = chat.invoke(messages)

            decision = self._parse_llm_response(response)
            
            # Enforce the wait threshold rule: only allow wait state when enough votes support it.
            if decision.get("action_type") == "wait" and not wait_threshold_met:
                print(f"Wait votes ({wait_votes}) are below the threshold (4). Selecting the highest-voted element instead of waiting")
                
                # If any element received votes, choose the highest-voted element.
                if vote_result:
                    top_xpath, vote_count = vote_result[0]
                    # Build a decision from the highest-voted element.
                    decision = {
                        "action_type": "click",  # Default to click.
                        "xpath": top_xpath,
                        "reason": f"Wait votes were insufficient, so the highest-voted element was selected ({vote_count} votes)",
                        "expected_outcome": "Try to advance the flow",
                        "wait_votes": wait_votes,  # Keep vote information for later checks.
                        "wait_threshold_met": wait_threshold_met
                    }
                else:
                    # If no element received votes, return an error.
                    decision = {
                        "error": "Unable to make a valid decision: wait votes are insufficient and no usable element is available",
                        "wait_votes": wait_votes,
                        "wait_threshold_met": wait_threshold_met
                    }
            
            # Add voting information to the decision for execution-time use.
            if decision.get("action_type") == "wait":
                decision["wait_votes"] = wait_votes
                decision["wait_threshold_met"] = wait_threshold_met
            
            # Record the expected result.
            if "expected_outcome" in decision:
                self.action_results["expected"] = decision["expected_outcome"]
                
            return decision

        except Exception as e:
            print(f"LLM decision failed: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}

    def _format_decision_errors(self, error_feedbacks):
        """
        Format decision-error experience so the LLM can avoid repeated mistakes.
        """
        formatted = ["🚫 Error-decision experience to focus on and avoid repeating:"]
        
        # Collect records marked as known bad elements.
        avoided_elements = [item for item in self.execution_feedback if item.get("action") == "avoided_bad_element"]
        
        # Process error-decision evaluation records.
        for i, item in enumerate(error_feedbacks[-3:], 1):  # Use only the latest three records.
            error_details = item.get("error_details", {})
            user_command = error_details.get("user_command", "unknown task")
            reason = error_details.get("reason", item.get("reason", "unknown reason"))
            
            page_eval = error_details.get("page_evaluation", {})
            mismatch_reason = page_eval.get("reason", "page does not match the task goal")
            recommended_action = page_eval.get("recommended_action", "go back to the previous page")
            
            # Get related error-decision information.
            prev_decision = error_details.get("previous_decision", {})
            decision_reason = prev_decision.get("reason", "unknown reason")
            error_xpath = prev_decision.get("xpath", "unknown path")
            
            # Build an error-decision experience entry.
            error_entry = f"{i}. While executing task '{user_command}', the system chose a wrong operation path because of '{decision_reason}', "
            error_entry += f"which caused '{mismatch_reason}'. Recommended improvement: {recommended_action}"
            
            # Add a specific element identifier to help the model recognize the bad element.
            if error_xpath != "unknown path":
                error_entry += f" [Avoid choosing xpath: {error_xpath}]"
            
            formatted.append(error_entry)
        
        # Add records for bad elements that were successfully avoided.
        if avoided_elements:
            formatted.append("\n🔄 Bad elements successfully avoided during execution:")
            for i, item in enumerate(avoided_elements[-3:], 1):  # Show only the latest three records.
                xpath = item.get("xpath", "unknown path")
                reason = item.get("reason", "unknown reason")
                formatted.append(f"{i}. Automatically avoided choosing element with xpath '{xpath}'. Reason: {reason}")
        
        # Add experience summary and suggestions.
        if error_feedbacks or avoided_elements:
            formatted.append("\n💡 Decision suggestions:")
            formatted.append("- When multiple interactable elements exist, prefer the element whose text exactly matches the target.")
            formatted.append("- When uncertain, prefer exploration and avoid directly operating buttons that may change state.")
            formatted.append("- For similar pages, refer to the error experience above and avoid the same decision mistake.")
            formatted.append("- Important: never choose the known bad element paths listed above.")
        
        return "\n".join(formatted)

    def _multi_thread_predict(self, messages, element_prompts, system_prompt_content, num_threads=5):
        """Use multiple threads to predict candidate elements."""
        predictions = [None] * num_threads
        threads = []

        # Get the bad-element XPath list.
        error_xpaths = []
        for item in self.execution_feedback:
            if item.get("action") == "avoided_bad_element" and "xpath" in item:
                error_xpaths.append(item["xpath"])
                
        for item in self.execution_feedback:
            if item.get("action") == "decision_error_evaluation":
                error_details = item.get("error_details", {})
                prev_decision = error_details.get("previous_decision", {})
                if "xpath" in prev_decision:
                    error_xpaths.append(prev_decision["xpath"])

        # Record the start time for logging.
        start_time = time.time()
        print(f"Starting multi-thread prediction. Thread count: {num_threads}")
        for idx, msg in enumerate(messages, 1):
            print(f"[*]message{idx} :{msg}")
        print(f"[*]element_prompts :{element_prompts}")
        # input()
        def predict(idx):
            try:
                # Record the thread start time.
                thread_start = time.time()
                print(f"Thread {idx} started")
                
                # Each thread calls the LLM independently for prediction.
                
                response = self.openai_client.chat.completions.create(
                    model="deepseek-reasoner",  # The yunwu-gpt4 name was only a local alias; gpt-4 is sufficient in practice.
                    messages=[
                        {"role": "system", "content": system_prompt_content},
                        {"role": "user", "content": "\n".join(messages)}
                    ],
                    stream=False,
                    temperature=0.2
                )
                
                #chat = ChatZhipuAI(model="glm-4-plus", temperature=0.5, top_p=0.7, max_tokens=1000)
                #response = chat.invoke(messages + [element_prompts])
                print(f"response : {response}")
                # input()
                prediction = self._parse_llm_response(response)
                
                # Validate the prediction and ensure it does not contain known bad elements.
                if "xpath" in prediction and prediction["xpath"] in error_xpaths:
                    print(f"Thread {idx} prediction contains a known bad element and will be excluded: {prediction['xpath']}")
                    # Replace with a short wait decision to avoid choosing the bad element.
                    prediction = {
                        "action_type": "wait", 
                        "reason": f"Avoiding known bad element {prediction['xpath']} and entering a temporary wait state",
                        "wait_time": 2
                    }
                
                predictions[idx] = prediction
                thread_end = time.time()
                print(f"Thread {idx} completed in {thread_end - thread_start:.2f}s")
            except Exception as e:
                print(f"Thread {idx} prediction failed: {str(e)}")
                traceback.print_exc()
                predictions[idx] = {"error": str(e)}

        # Create and start threads.
        for i in range(num_threads):
            t = threading.Thread(target=predict, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads to complete.
        for t in threads:
            t.join()

        # Calculate total execution time.
        end_time = time.time()
        total_time = end_time - start_time
        print(f"✅ Multi-thread prediction completed. Total time: {total_time:.2f}s, average per thread: {total_time/num_threads:.2f}s")
        
        # Check prediction results.
        valid_predictions = [p for p in predictions if p and not p.get("error")]
        print(f"📊 Prediction stats - total: {len(predictions)}, valid: {len(valid_predictions)}, failed: {len(predictions) - len(valid_predictions)}")
        
        return predictions

    def _collect_predictions(self, predictions):
        """Collect prediction results and vote."""
        vote_counts = {}
        wait_votes = 0  # Wait vote count.
        num_threads = len(predictions)  # Total thread count used for threshold calculation.
        
        # Get the bad-element XPath list.
        error_xpaths = []
        for item in self.execution_feedback:
            if item.get("action") == "avoided_bad_element" and "xpath" in item:
                error_xpaths.append(item["xpath"])
                
        for item in self.execution_feedback:
            if item.get("action") == "decision_error_evaluation":
                error_details = item.get("error_details", {})
                prev_decision = error_details.get("previous_decision", {})
                if "xpath" in prev_decision:
                    error_xpaths.append(prev_decision["xpath"])
        
        # Count votes, including wait state and element operations.
        for pred in predictions:
            # Check whether this is a wait decision.
            if pred and pred.get("action_type") == "wait":
                wait_votes += 1
                continue
                
            # Process votes for element operations.
            if pred and "xpath" in pred:
                xpath = pred["xpath"]
                # Skip known bad elements.
                if xpath in error_xpaths:
                    print(f"Excluding known bad element from vote counting: {xpath}")
                    continue
                    
                if xpath not in vote_counts:
                    vote_counts[xpath] = 0
                vote_counts[xpath] += 1
        
        # Sort by vote count in descending order.
        vote_result = sorted(vote_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Determine whether wait votes reached the threshold.
        wait_threshold_met = wait_votes >= 4
        
        # Output voting results, including wait-state votes.
        if vote_result or wait_votes > 0:
            print(f"Vote result: {vote_result}")
            print(f"Wait-state votes: {wait_votes}/{num_threads}")
            print(f"Wait threshold reached (requires 4 votes): {'Yes' if wait_threshold_met else 'No'}")
            if error_xpaths:
                print(f"Excluded bad elements: {error_xpaths}")
        else:
            print("No valid vote result was obtained")
            # If no valid vote result exists, all elements may have been excluded.
            if error_xpaths:
                print(f"Possible reason: all predicted elements are in the bad-element list: {error_xpaths}")
        
        # Return element votes, wait votes, thread count, and threshold status.
        return {
            "vote_result": vote_result,
            "wait_votes": wait_votes,
            "total_threads": num_threads,
            "wait_threshold_met": wait_threshold_met
        }

    def _format_action_feedback(self, feedback_list):
        """Format operation feedback records for prompts."""
        if not feedback_list:
            return "No historical operation feedback"
            
        formatted = ["Historical operation feedback that should influence decisions:"]
        
        # Check wait-failure feedback first and put it at the top.
        wait_fail_feedback = []
        for item in feedback_list:
            if item.get("action") == "wait_failed":
                wait_fail_feedback.append(f"⚠️ Wait state failed - ❌Failed - {item.get('reason', 'no reason')}")
        
        # Put wait-failure feedback before other feedback.
        if wait_fail_feedback:
            formatted.append("[Important] Wait-state failure records:")
            for i, feedback in enumerate(wait_fail_feedback[-2:], 1):  # Use only the latest two records.
                formatted.append(f"{i}. {feedback}")
            
        # Add other general feedback.
        general_feedback = []
        for item in feedback_list:
            if item.get("action") != "wait_failed":  # Exclude wait-failure feedback already added above.
                status = "✅Success" if item.get("success", False) else "❌Failed"
                action = item.get("action", "unknown operation")
                reason = item.get("reason", "no reason")
                general_feedback.append(f"{action} - {status} - {reason}")
        
        # Add general feedback.
        if general_feedback:
            formatted.append("\nGeneral operation feedback:")
            for i, feedback in enumerate(general_feedback[-5:], 1):  # Use only the latest five records.
                formatted.append(f"{i}. {feedback}")
            
        return "\n".join(formatted)
        
    def _format_reflections(self):
        """Format reflection records."""
        if not self.reflection_history:
            return ""
            
        formatted = ["Operation reflections and experience summaries for decision making:"]
        
        # Extract wait-related reflections.
        wait_reflections = []
        general_reflections = []
        
        for reflection in self.reflection_history:
            if "wait" in reflection.lower():
                wait_reflections.append(reflection)
            else:
                general_reflections.append(reflection)
        
        # Add wait-related reflections if any.
        if wait_reflections:
            formatted.append("[Wait-related reflections]")
            for i, reflection in enumerate(wait_reflections[-2:], 1):  # Use only the latest two records.
                formatted.append(f"{i}. {reflection}")
        
        # Add general reflections.
        if general_reflections:
            if wait_reflections:  # Add a separator if wait reflections exist.
                formatted.append("\n[Other general reflections]")
            for i, reflection in enumerate(general_reflections[-3:], 1):  # Use only the latest three records.
                formatted.append(f"{i}. {reflection}")
            
        return "\n".join(formatted)
    
    def _build_element_context(self, elements: list) -> str:
        """Build page element context with priority sorting and interaction markers."""
        high_priority = []  # High-priority elements.
        normal_priority = []  # Normal-priority elements.
        low_priority = []  # Low-priority elements, usually known bad elements.
        
        # Get known bad element XPath values.
        error_xpaths = []
        
        # Collect bad element XPath values from execution feedback.
        for item in self.execution_feedback:
            if item.get("action") == "avoided_bad_element" and "xpath" in item:
                error_xpaths.append(item["xpath"])
                
        # Collect bad element XPath values from error-decision evaluations.
        error_feedbacks = [fb for fb in self.execution_feedback if fb.get("action") == "decision_error_evaluation"]
        for item in error_feedbacks:
            error_details = item.get("error_details", {})
            prev_decision = error_details.get("previous_decision", {})
            if "xpath" in prev_decision:
                error_xpaths.append(prev_decision["xpath"])
        
        for element in elements:
            try:
                # Collect element features.
                element_info = self._capture_element_info(element)
                
                # Generate and store XPath for the element.
                element_info['generated_xpath'] = self._generate_xpath(element_info, element)
                
                # Check whether this is a known bad element.
                is_error_element = element_info['generated_xpath'] in error_xpaths
                element_info['is_error_element'] = is_error_element
                
                # Assign priority by interactability and error history.
                if is_error_element:
                    # Put known bad elements into the low-priority list.
                    low_priority.append(element_info)
                elif (element_info['clickable'] == 'true' or 
                    element_info['long-clickable'] == 'true' or
                    "edit" in element_info['class'].lower()):
                    # Add clicked-state information.
                    element_info['clicked_before'] = element_info['generated_xpath'] in self.excluded_xpaths
                    
                    # Lower priority for clicked elements, but do not exclude them.
                    if element_info['clicked_before']:
                        normal_priority.append(element_info)
                    else:
                        high_priority.append(element_info)
                else:
                    # Put non-interactive elements, such as plain text, into normal priority.
                    normal_priority.append(element_info)
            except StaleElementReferenceException:
                continue
                
        # Merge lists with high-priority elements first and known bad elements last.
        sorted_elements = high_priority + normal_priority + low_priority
        
        context = ["Current operable page elements. ★ means interactable; ⚠️ means the element caused an error before:"]
        for idx, info in enumerate(sorted_elements, 1):
            # Add interaction-state markers.
            interact_flags = []
            if info['clickable'] == 'true':
                interact_flags.append("clickable")
            if info['long-clickable'] == 'true':
                interact_flags.append("long-clickable")
            if "edit" in info['class'].lower():
                interact_flags.append("inputtable")
            if "button" in info['class'].lower():
                interact_flags.append("IsButton")
                
            operate = ""
            if "edit" in info['class'].lower():
                operate += "input text, "
            elif info['clickable'] == 'true':
                operate = 'click'
            elif info['long-clickable'] == 'true':
                operate = "long-click"
                
            # Check whether this is a known bad element.
            error_warning = ""
            if info.get('is_error_element', False):
                error_warning = "⚠️ This element caused an error before. Strongly avoid selecting it"
            
            # Describe clicked state instead of exclusion.
            clicked_status = "clicked before; priority lowered" if info['generated_xpath'] in self.excluded_xpaths else "not clicked yet"
            if error_warning:
                clicked_status = error_warning
            
            desc = [
                f"Element {idx}: " + ("★ " if interact_flags else "") + ("⚠️ " if info.get('is_error_element', False) else ""),
                f"Operation type: {operate}",
                f"Text: {info['text']}" if info['text'] else "" + (info['content-desc'] if info['content-desc'] else ""),
                f"ID: {info['resource-id']}" if info['resource-id'] else "",
                f"Class: {info['class'].split('.')[-1]}",
                f"Interaction: {','.join(interact_flags) if interact_flags else 'none'}",
                f"XPath: {info['generated_xpath']}",
                f"State: {clicked_status}",
                f"Child text info: " + (info['child_info'] if info['child_info'] else "")
            ]

            context.append(" | ".join([d for d in desc if d]))
            
        # Add a known-bad element reminder if needed.
        if error_xpaths:
            context.append("\n⚠️ Important reminder: elements marked with ⚠️ caused bad decisions before. Their priority has been lowered automatically; strongly avoid selecting them.")
            
        return "\n".join(context)

    def _parse_llm_response(self, response: AIMessage) -> dict:
        """Parse the LLM response and extract the first JSON object."""
        try:
            response_content = response.content
        except Exception:
            response_content = response.choices[0].message.content
        print(f"Response content: \n{response_content}\n")

        #try:
            # Find JSON start and end markers.
            #start_marker = '```json'
            #end_marker = '```'

            # Locate the first "```json" marker.
            #start = response_content.find(start_marker)
            #if start == -1 or response_content[start + len(start_marker) + 1] != '{':  # The response does not contain a "```json" marker.
                #print("The response does not contain a valid '```json' marker.")
                # raise ValueError("JSON start marker not found")
        try:
            # Locate JSON start and end positions.
            start = response_content.find('{')
            end = response_content.rfind('}')

            # Check whether valid JSON was found.
            if start == -1 or end == -1:
                raise ValueError("Valid JSON data was not found")

            # Extract the JSON string.
            json_str = response_content[start:end+1].strip()

            # Try to load JSON.
            result = self.process_json_string(json_str)
            if 'action_type' not in result:
                # Infer automatically from element attributes.
                if 'wait' in response_content.lower() or 'waiting' in response_content.lower():
                    # Recognize as wait state.
                    result["action_type"] = 'wait'
                    if 'wait_time' not in result:
                        # Default wait time.
                        result["wait_time"] = 10
                elif 'text' in response_content.lower() or 'input' in response_content.lower():
                    # Use "adb input".
                    result["action_type"] = 'text_input'
                elif 'long_click' in response_content.lower():
                    result["action_type"] = 'long_click'
                else:
                    result["action_type"] = 'click'
            # Ensure wait actions have wait_time.
            if result.get('action_type') == 'wait' and 'wait_time' not in result:
                result["wait_time"] = 30  # Default wait time.
            return result

        except (json.JSONDecodeError, ValueError) as e:
            print(f"Response parsing failed: {str(e)}")
            traceback.print_exc()
            return {"error": "invalid response format"}


    def execute_user_operation(self, user_command: dict, user_info: dict) -> bool:
        """
        Main entry point for executing user instructions with agent enhancements.
        
        Args:
            user_command: User command as JSON; the key is operation type, such as "添加设备", and the value is the detailed instruction.
            user_info: User information dictionary.
            
        Returns:
            bool: Whether the operation succeeded.
        """
        self.user_info = user_info
        try:
            # Ensure the dictionary contains at least one key-value pair.
            if len(user_command) == 0:
                print("Error: user_command cannot be empty")
                return False
                
            # Extract the first key-value pair as operation type and detailed instruction.
            operation_type = list(user_command.keys())[0]  # Operation type.
            operation_detail = user_command[operation_type]  # Detailed instruction.
            
            print(f"Starting operation: {operation_type} - {operation_detail}")
            
            self._navigate_to_homepage()
            self.operation_flow = []
            is_roll = True
            step_count = 0
            max_steps = 15  # Prevent infinite loops.

            # State tracking variables.
            self.excluded_xpaths = []  # Excluded XPath list.
            click_counts = defaultdict(int)  # Click counter per XPath.
            current_attempts = 0  # Number of different controls tried in the current state.
            last_state = None  # Previous page state signature.
            
            # Clear page structure history and start fresh loop detection.
            self.page_structure_history.clear()
            
            # Operation feedback tracking.
            operation_success = True
            failed_actions = []
            action_patterns = []  # Operation patterns.
            
            # Error recovery variables.
            recovery_mode = False  # Whether recovery mode is active.
            recovery_count = 0  # Recovery attempt count.
            decision_error_reported = False  # Whether a decision error has been reported.
            last_decision = None  # Last decision.

            # Wait-state variables.
            in_waiting_state = False  # Whether the scanner is in wait state.
            waiting_start_time = 0  # Wait-state start time.
            waiting_timeout_occurred = False  # Whether a wait timeout has occurred.
            waiting_timeout_threshold = 30  # Wait timeout threshold in seconds.

            while step_count < max_steps:
                # Get current page state signature.
                current_state = self._get_state_signature()
                print(f"current_state:\n{current_state}\n")
                
                # Check page loops without being affected by element state changes.
                if self._check_page_loop(self.page_structure_history):
                    print("⚠️ Page loop detected. Stopping operation execution")
                    self.execution_feedback.append({
                        "action": operation_type,
                        "success": True,  # Treat as success because a loop usually means the operation endpoint was reached.
                        "timestamp": time.time(),
                        "reason": "Page structure loop detected; operation flow completed"
                    })
                    # Add a reflection record.
                    self._add_reflection(f"Detected a page structure loop while executing '{operation_type}', so the operation is complete")
                    return True  # Return success when a loop is detected.

                # Add to history only when the state changes, using the adaptive threshold.
                if not self.is_similar_state(current_state, last_state):
                    self.sign_state_history.append(current_state)
                    print(f"self.sign_state_history count: {len(self.sign_state_history)}")
                    # Save to file.
                    with open("page_signatures.txt", "a", encoding="utf-8") as f:
                        f.write(f"{current_state}\n")
                    
                    # If in wait state, a state change means waiting has completed.
                    if in_waiting_state:
                        elapsed = time.time() - waiting_start_time
                        print(f"Page change detected during wait state after {elapsed:.1f}s. Exiting wait state")
                        in_waiting_state = False
                        waiting_timeout_occurred = False  # Reset timeout flag because waiting completed successfully.
                                            
                        # Add success feedback.
                        self.execution_feedback.append({
                            "action": operation_type,  # Use the original user command.
                            "success": True,
                            "timestamp": time.time(),
                            "reason": f"Page change detected during waiting after {elapsed:.1f}s"
                        })
                    
                    # # Evaluate page alignment after entering a new page.
                    # if step_count > 0 and not recovery_mode:  # Exclude the initial page and recovery mode.
                    #     page_evaluation = self._evaluate_page_goal_alignment(operation_type, operation_detail)
                    #     print(f"page_evaluation:\n{page_evaluation}\n")
                    #     if not page_evaluation["page_matches_goal"] and ('go back' in page_evaluation["recommended_action"]):
                    #         print(f"⚠️ Page goal mismatch. Reason: {page_evaluation['reason']}")
                    #         print(f"Suggested action: {page_evaluation['recommended_action']}")
                            
                    #         # Record decision-error information.
                    #         if not decision_error_reported:
                    #             self._record_decision_error(operation_type, page_evaluation, last_decision)
                    #             decision_error_reported = True
                            
                    #         # Enter recovery mode.
                    #         recovery_mode = True
                            
                    #         # Try to recover from the wrong state.
                    #         if self._recover_from_wrong_decision():
                    #             recovery_mode = False  # Recovery succeeded.
                    #             recovery_count = 0  # Reset the recovery counter.
                    #             print("✅ Recovered from the wrong decision")
                                
                    #             # Extra feedback: record the successful recovery reflection for the next decision.
                    #             reflection_text = f"Avoided loop exit while executing '{operation_type}': recovered from the wrong decision to a relevant page"
                    #             self._add_reflection(reflection_text)
                                
                    #             # Record avoided bad-element information.
                    #             if last_decision and "xpath" in last_decision:
                    #                 error_xpath = last_decision["xpath"]
                    #                 error_info = f"While executing '{operation_type}', avoided choosing element xpath '{error_xpath}' because it moved the page away from the target"
                    #                 self._add_reflection(error_info)
                                    
                    #                 # Add error-decision data to execution feedback so the model can use it.
                    #                 self.execution_feedback.append({
                    #                     "action": "avoided_bad_element",
                    #                     "xpath": error_xpath,
                    #                     "timestamp": time.time(),
                    #                     "reason": page_evaluation['reason']
                    #                 })
                                
                    #             # After successful recovery, adjust history state to avoid loop-detection interference.
                    #             if len(self.sign_state_history) > 2:
                    #                 self.sign_state_history.pop()  # Remove the latest wrong state.
                    #         else:
                    #             # Recovery failed; increment the recovery counter.
                    #             recovery_count += 1
                    #             if recovery_count >= 3:  # Allow up to three recovery attempts.
                    #                 print("❌ Too many recovery attempts. Continuing execution")
                    #                 recovery_mode = False  # Force exit from recovery mode.
                    #             else:
                    #                 # Allow multiple recovery attempts.
                    #                 print(f"⚠️ Recovery attempt {recovery_count} failed. Trying again...")
                    #                 time.sleep(1.5)  # Brief wait.
                    #                 continue  # Jump to the start of the loop and evaluate the page again.
                    #     else:
                    #         recovery_mode = False  # Page matches, so reset recovery mode.
                    #         recovery_count = 0  # Reset the recovery counter.

                        # Detect loops.
                        found_similar = 0
                        if len(self.sign_state_history) > 1:
                            for historical_state in self.sign_state_history[:-1]:
                                if self.is_similar_state(current_state, historical_state):
                                        found_similar += 1
                                        # Only stop on loops outside recovery mode to avoid false positives during recovery.
                                        if found_similar >= 2 and not recovery_mode:
                                                print("State loop detected. Operation flow completed")
                                                self.execution_feedback.append({
                                                    "action": operation_type,
                                                    "success": True,
                                                    "timestamp": time.time(),
                                                    "reason": "State loop detected; operation flow completed"
                                                })
                                                return True

                    
                # Check whether wait state timed out.
                if in_waiting_state and (time.time() - waiting_start_time > waiting_timeout_threshold):
                    print(f"Wait state timed out after {waiting_timeout_threshold}s with no page change. Exiting wait state")
                    in_waiting_state = False
                    is_roll = False
                    waiting_timeout_occurred = True  # Mark that a wait timeout occurred.
                    
                    # Add explicit wait-failure feedback so the LLM knows the wait failed.
                    self.execution_feedback.append({
                        "action": "wait_failed",
                        "success": False,
                        "timestamp": time.time(),
                        "reason": f"No page change after waiting {waiting_timeout_threshold}s; do not try wait state again"
                    })
                    
                    # Add a reflection record.
                    self._add_reflection(f"Wait operation timed out after {waiting_timeout_threshold}s with no page change. Avoid choosing wait again and try other interactable elements")

                # Reset related variables when the state changes, using the adaptive threshold.
                if not self.is_similar_state(current_state, last_state):
                    print(f"⚠️ Page state change detected")
                    print(f"  - Previous state: {last_state[:20] if last_state else 'None'}...")
                    print(f"  - New state: {current_state[:20]}...")
                    
                    click_counts.clear()
                    current_attempts = 0
                    last_state = current_state
                    print(f"Entered a new page state. Resetting exclusion list and counters")
                    
                    # Reset page exploration state.
                    self._reset_page_exploration_state()
                    
                    # Record the state transition as an observation.
                    self.observation_cache["state_change"] = {
                        "from": last_state,
                        "to": current_state,
                        "timestamp": time.time()
                    }

                # Detect state loops.
                if self.state_history.count(current_state) >= 5:
                    print("State loop detected. Stopping flow")
                    
                    # Record the failure pattern and reflection.
                    self._add_reflection(f"Detected a state loop while executing '{operation_type}'. This may be caused by UI element location issues or an app logic loop")
                    self.execution_feedback.append({
                        "action": operation_type,
                        "success": False,
                        "timestamp": time.time(),
                        "reason": "State loop"
                    })
                    
                    return False
                
                # If currently in wait state, check for timeout.
                if in_waiting_state:
                    elapsed = time.time() - waiting_start_time
                    if elapsed >= wait_timeout:
                        print(f"Wait timed out after {wait_timeout}s with no page change")
                        in_waiting_state = False
                        
                        # Add timeout feedback.
                        self.execution_feedback.append({
                            "action": operation_type,  # Use the original user command.
                            "success": False,
                            "timestamp": time.time(),
                            "reason": f"No page change after waiting {wait_timeout}s; manual action may be needed"
                        })
                        
                        # Increment the step count and continue trying other operations.
                        step_count += 1
                        continue
                    else:
                        # In wait state, check state changes every 6 seconds.
                        time.sleep(6)
                        continue

                # Perform page exploration.
                if is_roll is True:
                    # Get the current page signature.
                    current_signature = self._get_state_signature()
                    
                    # During decision making, only collect currently visible interactable controls.
                    print("⭐ Decision phase: collecting only current interactable control information...")
                    # Clear and recollect elements.
                    self.collected_elements_xpath.clear()
                    self.collected_elements.clear()
                    # Get currently visible elements directly.
                    for el in self._base_get_elements():
                        self.collected_elements.add(el)
                        try:
                            info = self._capture_element_info(el)
                            xpath = info['generated_xpath']
                            if xpath not in self.collected_elements_xpath:
                                print(f"Collected new element: {xpath}")
                                self.collected_elements_xpath.add(xpath)
                                self.collected_elements.add(el)
                            if "edittext" in info['class'].lower() and info["focused"] == "true":
                                print("Preparing to enter text, so page exploration is skipped")
                        except StaleElementReferenceException:
                            continue
                        # print(f"Added control element: {el}")
                    print(f"Interactable control count: {len(self.collected_elements)}")
                    
                    # Update the page signature without marking the page as explored.
                    self.current_page_signature = current_signature

                # Get and filter operable elements.
                elements = self._filter_elements(self.collected_elements)
                filtered_elements = []
                filtered_xpath = []
                for el in elements:
                    try:
                        info = self._capture_element_info(el)
                        xpath = info['generated_xpath']
                        if xpath not in self.excluded_xpaths:
                            filtered_elements.append(el)
                            filtered_xpath.append(xpath)
                    except StaleElementReferenceException:
                        continue
                elements = filtered_elements
                
                # If many operable elements are found, perform page exploration.
                if len(filtered_elements) >= 8 and is_roll is True:  # This threshold can be adjusted.
                    print("Many operable elements found. Starting page exploration...")
                    self.collected_elements_xpath.clear()
                    self.collected_elements.clear()
                    self._explore_full_page()
                    print(f"Element count after page exploration: {len(self.collected_elements_xpath)}")
                    
                    # Retrieve and filter elements again.
                    elements = self._filter_elements(self.collected_elements)
                    filtered_elements = []
                    filtered_xpath = []
                    for el in elements:
                        try:
                            info = self._capture_element_info(el)
                            xpath = info['generated_xpath']
                            if xpath not in self.excluded_xpaths:
                                filtered_elements.append(el)
                                filtered_xpath.append(xpath)
                        except StaleElementReferenceException:
                            continue
                    elements = filtered_elements
                else:
                    print("Few operable elements found, or the previous operation did not change page state. Skipping page exploration...")

                print(f"self.excluded_xpaths count: {len(self.excluded_xpaths)}")
                for fzy in self.excluded_xpaths:
                    print(f"self.excluded_xpaths element: {fzy}")
                print(f"filtered_elements count: {len(filtered_elements)}")
                
                if self.is_current_page_explored:
                    print("⭐ Current page has already been explored. Skipping repeated exploration")
                elif len(filtered_elements) < 4:
                    print("⭐ Few operable elements found. Skipping page exploration")
                elif not is_roll:
                    print("⭐ Previous operation did not change page state. Skipping page exploration")

                if not elements:
                    print("No operable elements found. Automatically entering wait state")
                    
                    # Record the reason.
                    wait_reason = f"No operable elements found while executing '{operation_type}'. Entering wait state for page changes"
                    self._add_reflection(wait_reason)
                    
                    # Set wait-state variables.
                    in_waiting_state = True
                    waiting_start_time = time.time()
                    wait_timeout = 30  # Default wait time.
                    
                    # Record the wait operation.
                    self._record_operation_step(
                        xpath="N/A", 
                        operation_type=operation_type,
                        reason=wait_reason,
                        element=None,
                        element_info={"type": "wait"}
                    )
                    
                    # Capture a screenshot at wait start.
                    screenshot_path = self._capture_screenshot(f"wait_start_{int(waiting_start_time)}.png")
                    print(f"Wait-start screenshot saved: {screenshot_path}")
                    
                    # Record execution feedback.
                    self.execution_feedback.append({
                        "action": "auto_wait",
                        "success": True,
                        "timestamp": time.time(),
                        "reason": wait_reason,
                        "wait_time": wait_timeout,
                        "screenshot_path": screenshot_path
                    })
                    
                    # Increment the step count and continue the loop.
                    step_count += 1
                    continue

                # Get the LLM decision with multi-thread prediction and voting.
                decision = self._get_llm_decision(operation_type, operation_detail, elements)
                last_decision = decision  # Save this decision for possible error-recovery records.
                
                if decision.get("status") == "complete":
                    print(f"LLM judged that the operation is complete: {decision}")
                    
                    # Record successful completion.
                    self.execution_feedback.append({
                        "action": operation_type,
                        "success": True,
                        "timestamp": time.time(),
                        "reason": decision.get("reason", "Operation complete")
                    })
                    
                    # Add a positive reflection on success.
                    self._add_reflection(f"The key to successfully executing '{operation_type}' was: {decision.get('reason', 'unknown')}")
                    
                    return True
                    
                # Check whether this is a wait-state operation.
                if decision.get("action_type") == "wait":
                    # If a wait timeout occurred before, skip wait state.
                    if waiting_timeout_occurred:
                        print("A previous wait operation timed out. Skipping this wait and choosing an interactable control")
                        # Record the decision to skip waiting.
                        self.execution_feedback.append({
                            "action": operation_type,  # Use the original user command.
                            "success": True,
                            "timestamp": time.time(),
                            "reason": "Previous wait timed out, so this wait operation was skipped"
                        })
                        continue  # Skip this decision and get a new one in the next loop.
                    
                    # Check whether the wait threshold requirement is met.
                    if not decision.get("wait_threshold_met", False):
                        print(f"Wait decision votes ({decision.get('wait_votes', 0)}) are below 4. Skipping wait")
                        self.execution_feedback.append({
                            "action": operation_type,
                            "success": False,
                            "timestamp": time.time(),
                            "reason": "Wait votes are insufficient; at least 4 votes are required to enter wait state"
                        })
                        continue  # Skip this decision and get a new one in the next loop.
                    
                    print(f"Entering wait state: {decision.get('reason', 'waiting for page changes')}, votes: {decision.get('wait_votes', 0)}")
                    
                    # Set wait-state variables.
                    in_waiting_state = True
                    waiting_start_time = time.time()
                    wait_timeout = decision.get("wait_time", 30)  # Default wait time.
                    
                    # Record the wait operation using the original user command.
                    self._record_operation_step(
                        xpath="N/A", 
                        operation_type=operation_type,  # Use the original user command.
                        reason=decision.get("reason", "Waiting for page changes"),
                        element=None,
                        element_info={"type": "wait"}
                    )
                    
                    # Capture a screenshot at wait start.
                    screenshot_path = self._capture_screenshot(f"wait_start_{int(waiting_start_time)}.png")
                    print(f"Wait-start screenshot saved: {screenshot_path}")
                    
                    # Record decision feedback.
                    self.execution_feedback.append({
                        "action": operation_type,  # Use the original user command.
                        "success": True,
                        "timestamp": time.time(),
                        "reason": f"Entering wait state: {decision.get('reason', 'waiting for page changes')}",
                        "wait_time": wait_timeout,
                        "screenshot_path": screenshot_path
                    })
                    
                    # Increment the step count and continue the loop.
                    step_count += 1
                    continue
                    
                if "xpath" not in decision:
                    print(f"Invalid decision response: {decision}")
                    
                    # Record failure.
                    self.execution_feedback.append({
                        "action": operation_type,
                        "success": False,
                        "timestamp": time.time(),
                        "reason": "LLM decision failed"
                    })
                    
                    return False

                # Execute the click operation.
                decision_xpath = decision["xpath"]
                xpath = self.find_most_similar(filtered_xpath, decision_xpath)
                print(
                    f"Step {step_count + 1}: {decision.get('reason', '')}, XPath: {xpath}, action type: {decision.get('action_type', '')}")
                
                # Record the expected result.
                if "expected_outcome" in decision:
                    print(f"Expected result: {decision['expected_outcome']}")

                try:
                    element = self.find_element_with_scroll(xpath)
                    if not element:
                        raise NoSuchElementException()

                except NoSuchElementException:
                    print(f"Element not found: {xpath}")
                    self.excluded_xpaths.append(xpath)
                    current_attempts += 1
                    
                    # Record element lookup failure.
                    failed_actions.append({
                        "xpath": xpath,
                        "reason": "Element not found",
                        "step": step_count
                    })

                    # execute page exploration to find more elements around the target xpath, which may help find the element or provide more context for the next decision.
                    self._explore_around_element(xpath)

                    if current_attempts >= 3:
                        print("Already tried 3 different controls without finding the element, stopping execution")
                        
                        # Record failure and reflection.
                        self._add_reflection(f"Executed '{operation_type}' but failed to find the target element after trying 3 different controls. This may be caused by inaccurate element information or page structure changes")
                        self.execution_feedback.append({
                            "action": operation_type,
                            "success": False,
                            "timestamp": time.time(),
                            "reason": "Element not found after multiple attempts"
                        })
                        
                        return False

                    continue

                element_info = self._capture_element_info(element)
                print(f"second generate {element}")
                success = self._perform_click_operation(element_info["generated_xpath"], decision=decision,
                                                        max_attempts=3)

                if success == 1:
                    # success, record the operation step with the original user command as the operation type.
                    self._record_operation_step(xpath, operation_type, decision.get("reason", ""), element, element_info)
                    step_count += 1
                    # reset exclusion list and counters because the page has changed successfully
                    current_attempts = 0
                    is_roll = True
                    self.excluded_xpaths = []
                    click_counts.clear()
                    
                    # record the successful operation with expected and actual outcomes for feedback.
                    action_outcome = {
                        "xpath": xpath,
                        "action_type": decision.get("action_type", "click"),
                        "success": True,
                        "actual_outcome": "Page state changed",
                        "expected_outcome": decision.get("expected_outcome", "not expected")
                    }
                    
                    # compare expected outcome with actual outcome to determine if the expectation is met, and record this in the feedback for more detailed learning signals.
                    expected = decision.get("expected_outcome", "")
                    if expected and "Page state changed" in expected:
                        action_outcome["expectation_met"] = True
                    
                    # record operation pattern for potential reflection on effective strategies. For example, if the decision reason contains certain keywords, we can categorize the action pattern.
                    action_patterns.append({
                        "element_type": element_info["class"],
                        "action": decision.get("action_type", "click"),
                        "success": True
                    })
                    
                    # Add to operation feedback.
                    self.action_results[xpath] = action_outcome
                    
                elif success == 2:  # text input success but no page change
                    is_roll = False
                    # text input is successful but page state does not change, which is common for input operations. We will not exclude the element immediately but will record the operation and rely on subsequent operations and feedback to determine whether to exclude it.
                    self._record_operation_step(xpath, operation_type, decision.get("reason", ""), element, element_info)
                    step_count += 1
                    if element_info["generated_xpath"] not in self.excluded_xpaths:
                        self.excluded_xpaths.append(element_info["generated_xpath"])
                        print(f"Excluded XPath: {element_info['generated_xpath']}")
                    # reset click counters because text input may not change page state immediately, and we want to allow subsequent operations on this element if needed.
                    current_attempts = 0
                    click_counts.clear()
                    
                    # record the text input operation with expected and actual outcomes for feedback.
                    self.action_results[xpath] = {
                        "xpath": xpath,
                        "action_type": "text_input",
                        "input_text": decision.get("input_text", ""),
                        "success": True,
                        "actual_outcome": "Text input succeeded but page did not change",
                        "expected_outcome": decision.get("expected_outcome", "not expected")
                    }
                elif success == 0:
                    # execution failed, likely due to the element being non-interactable. We will exclude this element and try other options.
                    print(f"Operation did not change page state. Adding element {xpath} to the exclusion list")
                    self.excluded_xpaths.append(xpath)
                    
                    # record the failed operation with reason for feedback.
                    click_counts[xpath] += 1
                    
                    # if an element has been clicked multiple times without causing a page change, it may be a non-interactive control. We can set a threshold (e.g., 3 clicks) to determine when to stop trying this element and move on to others.
                    if click_counts[xpath] >= 1:
                        print(f"Control {xpath} still caused no change after 1 click. It may be non-interactable")
                        current_attempts += 1
                        click_counts[xpath] = 0  # reset click count for this element to avoid repeated warnings, but it will still be in the exclusion list to prevent future attempts.
                        # is_roll = False  # set is_roll to False to skip page exploration in the next loop since the issue is likely with the element rather than the page state, but we will still try other elements on the same page.
                        
                        # check if we have tried multiple different elements without success, which may indicate a larger issue with the page state or the operation strategy, and we can choose to skip page exploration for a few attempts to see if other elements work.
                        if current_attempts >= 3:
                            print("has tried 3 different controls without finding a successful operation, stopping execution")
                            
                            # Record failure pattern and reflection.
                            self._add_reflection(f"executed '{operation_type}' but failed to find a successful operation after trying 3 different controls. This may be caused by inaccurate element information, page structure changes, or an ineffective operation strategy")
                            self.execution_feedback.append({
                                "action": operation_type,
                                "success": False,
                                "timestamp": time.time(),
                                "reason": "Multiple operations did not change state"
                            })
                            
                            return False

                # screenshot after each operation for feedback and analysis.
                screenshot_path = self._capture_screenshot(os.path.join("screenshot", f"step_{step_count}_screenshot.png"))
                if screenshot_path:
                    print(f"screenshot saved: {screenshot_path}")
                    # Add the screenshot path to operation feedback.
                    self.execution_feedback.append({
                        "action": operation_type,
                        "success": True,
                        "timestamp": time.time(),
                        "reason": "Post-operation screenshot",
                        "screenshot_path": screenshot_path
                    })

                time.sleep(2)  # Wait for the page to stabilize.

            print("reach maximum step count without completing the operation, stopping execution")
            
            # Record failure and reflection.
            self._add_reflection(f"Executing '{operation_type}' exceeded the step limit. The flow may be incomplete or looping")
            self.execution_feedback.append({
                "action": operation_type,
                "success": False,
                "timestamp": time.time(),
                "reason": "Maximum operation step limit reached"
            })
            
            return False
            
        except Exception as e:
            print(f"execution exception: {str(e)}")
            traceback.print_exc()
            
            # Record the exception.
            self.execution_feedback.append({
                "action": operation_type,
                "success": False,
                "timestamp": time.time(),
                "reason": f"Execution exception: {str(e)}"
            })
            self._stop_appium_server()
            
            return False

    def _add_reflection(self, reflection):
        """add a reflection record to the history, and keep the history length within 10."""
        self.reflection_history.append(reflection)
        if len(self.reflection_history) > 10:
            self.reflection_history.pop(0)  # keep only the latest 10 reflections
        print(f"📝 reflection: {reflection}")

    def _explore_around_element(self, xpath):
        """perform targeted exploration around a specific element based on its features, which may help find the element or provide more context for the next decision."""
        print(f"⭐ Performing targeted exploration around element: {xpath}")
        # Before exploration, save the current exploration state to avoid affecting the overall page exploration status. This allows us to perform targeted exploration without marking the page as explored, which can be beneficial for finding specific elements without interfering with the general exploration logic.
        original_explored_state = self.is_current_page_explored
        original_page_signature = self.current_page_signature
        
        # according to the xpath features, we can perform different exploration strategies. For example, if the xpath contains certain keywords that indicate the element is likely located in a specific area of the page, we can perform targeted swipes in that area to try to find the element.
        if 'add' in xpath.lower():
            self._smart_swipe('down')  # add buttons are often at the bottom
        elif 'menu' in xpath.lower():
            self._smart_swipe('left')  # menu buttons are often on the left
        else:
            self._smart_swipe('up')  # try swiping up by default to find elements that may be above the current view
            
        # After targeted exploration, we will not mark the page as explored to allow for future exploration if needed, and we will restore the original page signature to avoid interference with the overall exploration logic. This way, the targeted exploration can help find specific elements without affecting the general state of page exploration.
        self.is_current_page_explored = original_explored_state
        self.current_page_signature = original_page_signature
        print(f"⭐ Finished targeted exploration around element: {xpath}, restored original exploration state")

    def find_element_with_scroll(self, xpath, max_swipe=4):
        """try to find the element by performing smart swipes in multiple directions, and return the element if found and visible. This method is designed to handle cases where the element may not be initially visible on the screen and may require scrolling to be found."""
        if self.explore_horizontal:
            directions = ['down', 'up', 'right', 'left']
        else:
            directions = ['down', 'up']  # only explore vertically by default to reduce the risk of missing elements due to horizontal swipes, which can be more disruptive to the page state. Horizontal exploration can be enabled if needed for specific cases where elements are likely located horizontally.
        
        swipe_count = 0

        while swipe_count < max_swipe:
            try:
                print(f"find {xpath}")
                if xpath.startswith("class|"):
                    parts = xpath.split("|")
                    print("class find "+parts[1]+f" {int(parts[2]) - 1}")
                    silbins = self.driver.find_elements(AppiumBy.CLASS_NAME, parts[1])
                    element = silbins[int(parts[2]) - 1]
                else:
                    element = self.driver.find_element(AppiumBy.XPATH, xpath)
                print(f"can find element {element}")
                if self._is_element_visible(element):
                    print(f"{xpath} corresponding element is visible")
                    return element
            except NoSuchElementException:
                print(f"find {xpath} failed")
                pass

            for direction in directions:
                original_state = self._get_state_signature()
                self._smart_swipe(direction)
                
                while self._get_state_signature() != original_state:
                    try:
                        if xpath.startswith("class|"):
                            parts = xpath.split("|")
                            silbins = self.driver.find_elements(AppiumBy.CLASS_NAME, parts[1])
                            print("class find "+parts[1]+f"{int(parts[2]) - 1}")
                            element = silbins[int(parts[2]) - 1]
                        else:
                            element = self.driver.find_element(AppiumBy.XPATH, xpath)
                        if self._is_element_visible(element):
                            print(f"{xpath} corresponding element is visible")
                            return element
                    except NoSuchElementException:
                        pass
                    
                    original_state = self._get_state_signature()
                    self._smart_swipe(direction)
                    time.sleep(1)  
                
                swipe_count += 1
                time.sleep(1)

        print(f"{xpath} element not found after {max_swipe} swipes in each direction")
        return None

    def _smart_swipe(self, direction):
        """perform a swipe in the specified direction with improved logic to increase the chances of finding elements. The swipe coordinates are calculated based on the screen size, and the method includes print statements for debugging and analysis of swipe actions."""
        window = self.driver.get_window_size()
        swipe_config = {
            'down': (window['width'] * 0.5, window['height'] * 0.7, window['width'] * 0.5, window['height'] * 0.3),
            'up': (window['width'] * 0.5, window['height'] * 0.3, window['width'] * 0.5, window['height'] * 0.7),
            'left': (window['width'] * 0.7, window['height'] * 0.5, window['width'] * 0.3, window['height'] * 0.5),
            'right': (window['width'] * 0.3, window['height'] * 0.5, window['width'] * 0.7, window['height'] * 0.5)
        }
        self.driver.swipe(*swipe_config[direction], duration=800)
        print(f"executed smart swipe: {direction}, from ({swipe_config[direction][0]}, {swipe_config[direction][1]}) to ({swipe_config[direction][2]}, {swipe_config[direction][3]})")

    def _record_operation_step(self, xpath: str, operation_type: str, reason: str, element, element_info):
        """
        Record an operation step.
        
        Args:
            xpath: XPath of the operated element.
            operation_type: Operation type, such as "添加设备".
            reason: Operation reason.
            element: Operated element object.
            element_info: Element information dictionary.
        """
        action_type = ''
        if element_info.get('long-clickable') == 'true':
            action_type = 'long_click'
        elif element_info.get('type') == 'wait':
            action_type = 'wait'
        else:
            action_type = 'click'
        step_data = {
            "xpath": xpath,
            "action_type": action_type,
            "description": self._generate_description(element_info),
            "reason": reason,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        user = "user1" if "user1" in self.user_info.get("user", "").lower() else "user2"
        scope = "local" if "local" in self.user_info.get("scope", "").lower() else "remote"
        
        operation_name = self._detect_operation_from_command(operation_type, element_info)
        
        if operation_name:
            action_type = f"{user}|{scope}|{operation_name}"
            
            if operation_name not in self.json_config[user][scope]:
                # if the operation type does not exist, create a new operation record
                self.json_config[user][scope][operation_name] = {}
            
            # the step number is determined by the current number of steps recorded for this operation type, plus one for the new step. This way, we can keep track of the sequence of steps for each operation type.
            step_number = len(self.json_config[user][scope][operation_name]) + 1
            
            # create the step record with all necessary information, including the xpath, description, waiting time (if it's a wait operation), and input text (if applicable). This structured record allows us to have a clear and detailed log of each operation step for future reference and analysis.
            step_record = {
                "xpath": xpath,
                "description": step_data["description"],
                "waiting_time": element_info.get("wait_time", 0.1) if element_info.get("type") == "wait" else 0.1
            }
            
            # only if the operation involves text input, we will record the input text in the step record. This is important for understanding the context of the operation and for potential replay or analysis of the steps taken.
            input_text = element_info.get("input_text", "")
            if input_text and input_text.strip():
                step_record["input_text"] = input_text
                print(f"✏️ record input text: {input_text}")
            
            # add the step record to the JSON configuration under the appropriate user, scope, and operation type, using the step number as the key. This organized structure allows us to easily access and analyze the steps taken for each operation type under different users and scopes.
            self.json_config[user][scope][operation_name][str(step_number)] = step_record
            
            # add the operation type to the createDatabaseActionOrder list if it's not already there, which helps us keep track of the order of operations for database creation and other purposes. This list can be useful for understanding the sequence of operations and for potential replay or analysis of the operation flow.
            if action_type not in self.json_config["createDatabaseActionOrder"]:
                self.json_config["createDatabaseActionOrder"].append(action_type)
            
            
            self._save_config(self.save_path)
        
        self.operation_flow.append(step_data)

    def _detect_operation_from_command(self, operation_type: str, element_info: dict) -> str:
        """
        Detect the operation type name from operation type and element information.
        
        Args:
            operation_type: Operation type, such as "添加设备".
            element_info: Element information dictionary.
            
        Returns:
            str: Detected operation type code, such as "AddDevice".
        """
        # 1. Detect from operation type.
        if operation_type in operation_keywords:
            return operation_keywords[operation_type]
                
        # 2. Detect from element text.
        element_text = element_info.get("text", "")
        if element_text:
            if "添加" in element_text or "新增" in element_text:
                return "AddDevice"
            elif "分享" in element_text or "共享" in element_text:
                return "SharePlug"
            elif "接受" in element_text or "同意" in element_text:
                return "AcceptDeviceShare"
            elif "取消" in element_text and ("分享" in element_text or "共享" in element_text):
                return "UnsharePlug"
            elif "删除" in element_text or "移除" in element_text:
                return "RemoveDevice"
            elif "控制" in element_text:
                return "DeviceControl"
            
        # 3. Detect from resource ID.
        resource_id = element_info.get("resource-id", "")
        if resource_id:
            if "add" in resource_id.lower():
                return "AddDevice"
            elif "share" in resource_id.lower():
                return "SharePlug"
            elif "control" in resource_id.lower() or "switch" in resource_id.lower():
                return "DeviceControl"
                
        # Default to DeviceControl.
        return "DeviceControl"

    def _perform_click_operation(self, xpath, decision, max_attempts=3):
        """Perform an element operation and verify state changes. Supports click and long-click."""
        original_state = self._get_state_signature()
        retries = 0
        last_exception = None

        while retries < max_attempts:
            try:
                # Get the element and determine operation type.
                print(f"second click {xpath}")
                if xpath.startswith("class|"):
                    parts = xpath.split("|")
                    silbins = self.driver.find_elements(AppiumBy.CLASS_NAME, parts[1])
                    print("class find "+parts[1]+f"{int(parts[2]) - 1}")
                    element = silbins[int(parts[2]) - 1]
                else:
                    element = self.driver.find_element(AppiumBy.XPATH, xpath)
                
                element_info = self._capture_element_info(element)
                input_action_result = False
                action_result = False
                # Choose the operation method based on element attributes.
                if 'text' in decision["action_type"].lower() or 'input' in decision["action_type"].lower():
                    input_action_result = self._perform_input_operation(xpath, element_info, decision["input_text"])
                if element_info.get('long-clickable') == 'true' and ('long-clickable' in decision["action_type"]):
                    print(f"second long-clickable {xpath}")
                    action_result = self._perform_long_click(xpath)
                elif input_action_result is False:
                    print(f"second clickable {xpath}")
                    action_result = self._click_element(xpath)
                # if input text
                # if 'text' in decision["action_type"].lower() or 'input' in decision["action_type"].lower():
                #     input_command = f'input text {decision["input_text"]}'
                #     self.execute_adb_shell_command(input_command, root=False)
                #     self.driver.hide_keyboard()
                #     time.sleep(0.5)
                if input_action_result is True:
                    self.excluded_xpaths.append(xpath)
                    print(f"Excluded XPath: {xpath}")
                    changed_xpath = xpath[:xpath.find('=') + 1] + f"'{decision['input_text']}'" + xpath[
                                                                                                  xpath.find(']'):]
                    self.excluded_xpaths.append(changed_xpath)
                    changed_xpath = xpath[:xpath.find('=') + 1] + f'"{decision["input_text"]}"' + xpath[
                                                                                                  xpath.find(']'):]
                    self.excluded_xpaths.append(changed_xpath)
                    print(f"Excluded XPath: {changed_xpath}")
                    self.state_history.append(f"Entered text in input field {xpath}.")
                    #self.state_history.append(f"Device has operated {changed_xpath} element.")
                    # Pure text input does not change page state, so return 2.
                    return 2
                if action_result is False:
                    raise Exception("Operation execution failed")

                # Wait for the page to stabilize, then verify state changes.
                time.sleep(1.5)
                new_state = self._get_state_signature()
                # Use is_similar_state with the adaptive threshold to determine whether the state changed.
                if not self.is_similar_state(original_state, new_state):
                    print("Operation succeeded and page state changed")
                    self.state_history.append(f"Clicked control {xpath} element.")
                    return 1
                else:
                    print("No obvious page state change after operation; similarity is above threshold")

                retries += 1
                print(f"State did not change. Starting retry {retries}...")

            except (NoSuchElementException, StaleElementReferenceException) as e:
                last_exception = e
                print(f"Element state exception. Trying to refresh elements: {str(e)}")
                self._refresh_page_elements()
                retries += 1

            except Exception as e:
                last_exception = e
                print(f"Operation exception: {str(e)}")
                retries += 1

            # Wait before retrying.
            if retries < max_attempts:
                time.sleep(0.5 + retries * 0.3)

        print(f"Operation failed to change page state. Final error: {str(last_exception)}")
        self.state_history.append(f"Clicked control {xpath} element.")
        return 0

    def _perform_input_operation(self, xpath: str, element_info: dict, text: str) -> bool:
        """Perform text input."""
        try:
            element = self.find_element_with_scroll(xpath)
            if not element:
                return False

            # Clear existing content.
            element.clear()
            # Enter text.
            element.send_keys(text)
            print(f"Entered text at {xpath}: {text}")

            # Ensure the input text is recorded.
            element_info["input_text"] = text
            
            # Validate the input result if possible.
            if element.text != text:
                print("Input validation failed. Trying to enter text again")
                element.send_keys(text)

            return True
        except Exception as e:
            try:
                if element_info.get('long-clickable') == 'true':
                    action_result = self._perform_long_click(xpath)
                else:
                    action_result = self._click_element(xpath)
                if not action_result:
                    raise Exception("Operation execution failed")
                input_command = f'input text {text}'
                self.execute_adb_shell_command(input_command, root=False)
                self.driver.hide_keyboard()
                time.sleep(0.5)
                return True
            except Exception as e:
                print(f"Input operation failed: {str(e)}")
                return False

    def _click_element(self, xpath, max_retries=3):
        """Enhanced element click with smart wait and retry."""
        retries = 0
        while retries < max_retries:
            try:
                if xpath.startswith("class|"):
                    parts = xpath.split("|")
                    silbins = self.driver.find_elements(AppiumBy.CLASS_NAME, parts[1])
                    print("class find "+parts[1]+f"{int(parts[2]) - 1}")
                    element = silbins[int(parts[2]) - 1]
                else:
                    element = self.driver.find_element(AppiumBy.XPATH, xpath)
                #element = WebDriverWait(self.driver, 5).until(
                    #EC.element_to_be_clickable((AppiumBy.XPATH, xpath)))

                # Validate element state again before execution.
                if not element.is_displayed() or not element.is_enabled():
                    raise Exception("Element is not operable")

                # Use a more reliable click method.
                # self.driver.execute_script('mobile: click', {'elementId': element.id})
                actions = ActionChains(self.driver)
                actions.move_to_element(element).click().perform()
                print(f"Clicked element successfully: {xpath}")
                return True

            except StaleElementReferenceException:
                print(f"Element is stale. Trying to retrieve it again... ({retries + 1}/{max_retries})")
                retries += 1
                time.sleep(0.5)

            except Exception as e:
                print(f"Click exception: {str(e)}")
                traceback.print_exc()
                retries += 1
                time.sleep(0.3)

        print(f"Click failed after exceeding max retries: {max_retries}")
        return False

    def long_press_element(self, driver, element, duration=1000):
        """
        Use W3C actions to perform a long press.
        :param driver: Appium WebDriver
        :param element: Element to long-press.
        :param duration: Long-press duration in milliseconds.
        """
        actions = ActionChains(self.driver)
        # Set the action type to touch.
        actions.w3c_actions = ActionBuilder(self.driver, mouse=PointerInput(interaction.POINTER_TOUCH, "touch"))

        # Define the long-press action.
        actions.w3c_actions.pointer_action.move_to(element)  # Move to target element.
        actions.w3c_actions.pointer_action.pointer_down()  # Press down.
        actions.w3c_actions.pointer_action.pause(duration / 1000)  # Pause for the specified duration.
        actions.w3c_actions.pointer_action.release()  # Release.
        actions.perform()  # Execute the action.

    def _perform_long_click(self, xpath, duration=1500):
        """Perform long-click with state validation."""
        try:
            if xpath.startswith("class|"):
                parts = xpath.split("|")
                silbins = self.driver.find_elements(AppiumBy.CLASS_NAME, parts[1])
                print("class find "+parts[1]+f"{int(parts[2]) - 1}")
                element = silbins[int(parts[2]) - 1]
            else:
                element = self.driver.find_element(AppiumBy.XPATH, xpath)
            #element = WebDriverWait(self.driver, 5).until(
                #EC.presence_of_element_located((AppiumBy.XPATH, xpath)))

            original_state = self._get_state_signature()

            # Use TouchAction to perform long-click.
            self.long_press_element(self.driver, element, duration=2000)  # Long-press for 2 seconds.

            # Wait for possible animation effects.
            time.sleep(1.2)

            # Verify state changes after long-click.
            if self._get_state_signature() != original_state:
                print("Long-click operation succeeded")
                return True

            print("Long-click operation did not trigger a state change")
            return False

        except Exception as e:
            print(f"Long-click operation failed: {str(e)}")
            return False

    def _refresh_page_elements(self):
        """Refresh the page element cache."""
        try:
            self.driver.find_elements(AppiumBy.XPATH, "//*")  # Trigger element refresh.
            time.sleep(0.3)
        except:
            pass

    def _reset_to_homepage(self):
        """Reset to the home page."""
        self.driver.close_app()
        self.driver.launch_app()
        self._wait_for_homepage()

    def _is_operation_complete(self):
        """Check whether the operation is complete. Customize completion conditions as needed."""
        # Example condition: complete when back on the home page and the operation flow is not empty.
        return self._is_homepage() and len(self.operation_flow) > 0

    def _is_homepage(self):
        """Check whether the current page is the home page."""
        return self.driver.current_activity == self.json_config["homePage"]

    def _navigate_to_homepage(self):
        """Ensure navigation back to the home page."""
        if not self._is_homepage():
            self.driver.back()
            self._wait_for_homepage()

    def _generate_xpath(self, element_info, element):
        """Improved XPath generation method."""
        # Prefer resource-id for XPath generation.
        if element_info["resource-id"] and element_info["resource-id"] != "null":
            return f'//*[@resource-id="{element_info["resource-id"]}"]'

        # Use text content, which is suitable for button text.
        if element_info["text"] and element_info["text"] != '':
            text = element_info["text"].replace('"', "'")
            return f'//*[@text="{text}"]'

        # Use content description.
        if element_info["content-desc"] and element_info["content-desc"] != "null":
            desc = element_info["content-desc"].replace('"', "'")
            return f'//*[@content-desc="{desc}"]'

        # Use class name and index as the last resort.
        class_name = element_info["class"]
        index = self._get_element_index(class_name, element)
        return f'class|{class_name}|{index}'

    def _wait_for_homepage(self):
        WebDriverWait(self.driver, 30).until(
            lambda d: d.current_activity == self.json_config["appStartActivity"]
        )
        # Wait one second to avoid slow loading issues.
        time.sleep(1)
        self.json_config["homePage"] = self.driver.current_activity

    def _get_state_signature(self):
        """
        Get the current page state signature.
        Uses all interactable and non-interactable controls as page labels.
        """
        try:
            # Get page source.
            page_source = self.driver.page_source
            
            # Record features.
            features = []
            
            # 1. Add activity name.
            try:
                current_activity = self.driver.current_activity
                features.append(f"A:{current_activity}")
            except:
                pass
            
            # 2. Get all interactable elements.
            interactable_elements = self.driver.find_elements(AppiumBy.XPATH, 
                '//*[@clickable="true" or @longClickable="true" or contains(@class, "EditText")]')
            
            # Record interactable element features.
            for i, element in enumerate(interactable_elements):
                try:
                    # Get element type.
                    element_type = element.get_attribute("class").split(".")[-1]
                    resource_id = element.get_attribute("resource-id") or ""
                    resource_id = resource_id.split("/")[-1] if "/" in resource_id else resource_id
                    
                    # Get element position.
                    try:
                        location = element.location
                        size = element.size
                        position_str = f"@({location['x']},{location['y']})[{size['width']}x{size['height']}]"
                    except:
                        position_str = "@unknown"
                    
                    # Interactable state flags.
                    interact_flags = []
                    if element.get_attribute("clickable") == "true":
                        interact_flags.append("C")
                    if element.get_attribute("long-clickable") == "true":
                        interact_flags.append("L")
                    if "EditText" in element.get_attribute("class"):
                        interact_flags.append("E")
                    interact_flag = "".join(interact_flags)
                    
                    # Get element text.
                    text_content = element.get_attribute("text") or ""
                    content_desc = element.get_attribute("content-desc") or ""
                    display_text = text_content or content_desc
                    
                    # Combine interactable element features.
                    elem_sig = f"I:{element_type}:{resource_id[-15:]}:{interact_flag}:{display_text[:15]}:{position_str}"
                    features.append(elem_sig)
                except:
                    continue
            
            # 3. Get all non-interactable text elements on the page.
            non_interactable_elements = self.driver.find_elements(AppiumBy.XPATH, 
                '//*[@visible="true" and @clickable="false" and @long-clickable="false"]')
            
            for i, element in enumerate(non_interactable_elements):
                try:
                    # Get element type.
                    element_type = element.get_attribute("class").split(".")[-1]
                    
                    # Get element position.
                    try:
                        location = element.location
                        size = element.size
                        position_str = f"@({location['x']},{location['y']})[{size['width']}x{size['height']}]"
                    except:
                        position_str = "@unknown"
                    
                    # Get element text.
                    text_content = element.get_attribute("text") or ""
                    content_desc = element.get_attribute("content-desc") or ""
                    display_text = text_content or content_desc
                    
                    # Record only non-interactable elements that have text.
                    if display_text:
                        # Combine non-interactable element features.
                        elem_sig = f"N:{element_type}:{display_text[:15]}:{position_str}"
                        features.append(elem_sig)
                except:
                    continue
            
            # 4. Add brief page structure features.
            layout_types = ["LinearLayout", "RelativeLayout", "FrameLayout", 
                           "ConstraintLayout", "RecyclerView", "ListView",
                           "ScrollView", "ViewPager"]
            
            layout_counts = {}
            for layout in layout_types:
                count = page_source.count(layout)
                if count > 0:
                    layout_counts[layout] = count
            
            # Generate layout features.
            layout_features = []
            for layout, count in sorted(layout_counts.items(), key=lambda x: (-x[1], x[0]))[:3]:
                layout_features.append(f"{layout[:3]}={count}")
            
            if layout_features:
                features.append(f"L:{'-'.join(layout_features)}")
            
            # Combine all features.
            signature = "|".join(features)
            
            print(f"🔍 Generated page label with {len(features)} features")
            return signature
            
        except Exception as e:
            # Use a minimal signature on error.
            print(f"Error while getting state signature: {str(e)}")
            return f"ERROR_STATE:{time.time()}"
    
    def _extract_hierarchy_signature(self, page_source):
        """
        Extract a hierarchy signature from page source.
        Only element types and basic structure are extracted; concrete content is ignored.
        """
        try:
            # Extract major layout and control types.
            layout_types = []
            
            # Match common Android layout types.
            layout_patterns = [
                "LinearLayout", "RelativeLayout", "FrameLayout", 
                "ConstraintLayout", "RecyclerView", "ListView",
                "ScrollView", "ViewPager", "Toolbar", "ActionBar",
                "Button", "TextView", "ImageView", "EditText", "CheckBox",
                "RadioButton", "Switch", "ProgressBar", "Dialog"
            ]
            
            # Count each layout type.
            counts = {}
            for pattern in layout_patterns:
                count = page_source.count(pattern)
                if count > 0:
                    counts[pattern] = count
            
            # Generate signature as type=count.
            for layout_type, count in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
                layout_types.append(f"{layout_type[:3]}={count}")
            
            # Use the five most frequent types for the signature.
            return "-".join(layout_types[:5])
        except:
            return "unknown_hierarchy"
            
    def is_similar_state(self, state1, state2, threshold=None):
        """
        Check whether two states are similar using enhanced state signatures.
        
        Args:
            state1: First state signature.
            state2: Second state signature.
            threshold: Similarity threshold. Uses the adaptive threshold if omitted.
        """
        # Use the instance default threshold, which may have been dynamically adjusted.
        if threshold is None:
            threshold = self.similar_threshold
            
        if not state1 or not state2:
            return False
        if str(state1) == str(state2):
            return True
            
        # If completely identical.
        result = self.compare_last_line_with_previous(file_path="page_signatures.txt")
        if result:
            return True
        
        # Split feature sets.
        tokens1 = state1.split('|')
        tokens2 = state2.split('|')
        
        # Classify features by type.
        # I: interactable element, N: non-interactable element, A: activity name, L: layout feature.
        interactable1 = [t for t in tokens1 if t.startswith('I:')]
        interactable2 = [t for t in tokens2 if t.startswith('I:')]
        
        non_interactable1 = [t for t in tokens1 if t.startswith('N:')]
        non_interactable2 = [t for t in tokens2 if t.startswith('N:')]
        
        activity1 = [t for t in tokens1 if t.startswith('A:')]
        activity2 = [t for t in tokens2 if t.startswith('A:')]
        
        layout1 = [t for t in tokens1 if t.startswith('L:')]
        layout2 = [t for t in tokens2 if t.startswith('L:')]
        
        # Calculate similarity for each part.
        # 1. Interactable element similarity, the most important part.
        if interactable1 and interactable2:
            int_set1 = set(interactable1)
            int_set2 = set(interactable2)
            
            int_intersection = len(int_set1.intersection(int_set2))
            int_union = len(int_set1.union(int_set2))
            
            int_similarity = int_intersection / int_union if int_union > 0 else 0
        else:
            # If one state has interactable elements and the other does not, treat them as completely different.
            if (interactable1 and not interactable2) or (interactable2 and not interactable1):
                int_similarity = 0
            else:
                int_similarity = 1  # Treat as identical if neither has interactable elements.
        
        # 2. Non-interactable element similarity.
        if non_interactable1 and non_interactable2:
            non_int_set1 = set(non_interactable1)
            non_int_set2 = set(non_interactable2)
            
            non_int_intersection = len(non_int_set1.intersection(non_int_set2))
            non_int_union = len(non_int_set1.union(non_int_set2))
            
            non_int_similarity = non_int_intersection / non_int_union if non_int_union > 0 else 0
        else:
            # If there is no non-interactable text information, rely more on other factors.
            non_int_similarity = 0.5
        
        # 3. Activity name similarity.
        activity_similarity = 1.0 if activity1 == activity2 else 0.0
        
        # 4. Layout feature similarity.
        layout_similarity = 1.0 if layout1 == layout2 else 0.5  # Different layouts may still represent the same page.
        
        # Calculate weighted total similarity.
        # Interactable elements have the highest weight (50%), then non-interactable elements (30%),
        # activity name (15%), and layout features (5%).
        weighted_similarity = (
            0.5 * int_similarity + 
            0.3 * non_int_similarity + 
            0.15 * activity_similarity + 
            0.05 * layout_similarity
        )
        
        # Record similarity samples for adaptive threshold learning.
        if len(self.page_similarity_samples) < 100:  # Limit sample count.
            self.page_similarity_samples.append({
                "similarity": weighted_similarity,
                "timestamp": time.time(),
                "is_match": weighted_similarity >= threshold
            })
        
        # Judge using the provided threshold.
        return weighted_similarity >= threshold

    def _adjust_similarity_threshold(self, is_recovery_successful=False):
        """
        Dynamically adjust the page similarity threshold.
        The threshold is adjusted using recovery results and historical similarity samples.
        
        Args:
            is_recovery_successful: Whether recovery succeeded.
        """
        try:
            # Record the current threshold.
            old_threshold = self.similar_threshold
            
            # 1. Adjust based on recovery result.
            if is_recovery_successful:
                # If recovery succeeded, the threshold may be too low; increase it to be stricter.
                adjustment = 0.02
            else:
                # If recovery failed, the threshold may be too high; decrease it to be more tolerant.
                adjustment = -0.01
                
            # 2. Adjust based on historical sample statistics.
            if len(self.page_similarity_samples) >= 10:
                # Calculate sample distribution.
                similarities = [s["similarity"] for s in self.page_similarity_samples[-20:]]
                
                if similarities:
                    # Calculate sample statistics.
                    import statistics
                    try:
                        mean_sim = statistics.mean(similarities)
                        median_sim = statistics.median(similarities)
                        
                        # If mean and median differ greatly, the distribution is uneven and should be adjusted.
                        if abs(mean_sim - median_sim) > 0.1:
                            adjustment += 0.01 * (median_sim - self.similar_threshold)
                    except:
                        pass
            
            # Apply adjustment and keep the threshold in a reasonable range.
            new_threshold = max(0.7, min(0.95, self.similar_threshold + adjustment))
            
            # Record only meaningful changes.
            if abs(new_threshold - old_threshold) >= 0.01:
                self.similar_threshold = new_threshold
                
                # Record adjustment history.
                self.threshold_adjustment_history.append({
                    "old_threshold": old_threshold,
                    "new_threshold": new_threshold,
                    "timestamp": time.time(),
                    "reason": "Recovery " + ("succeeded" if is_recovery_successful else "failed")
                })
                
                print(f"⚙️ Page similarity threshold adjusted: {old_threshold:.3f} -> {new_threshold:.3f}")
                
        except Exception as e:
            print(f"Error while adjusting similarity threshold: {str(e)}")



    def traverse_element_and_collect_text(self, root_element):
        """
        Recursively traverse all child elements from root_element and collect all non-empty text.
        """
        collected_texts = []
        visited = set()

        def dfs(element, level):
            # Get the current element text.
            #print(f"level {level}, text {element}")
            if element.id not in visited:
                visited.add(element.id)
                #print(visited)
                text_val = element.get_attribute('text')
                if text_val and level != 0:  # Collect non-empty text.
                    collected_texts.append(text_val)
                    #print(f"level {level}, text {text_val}")

            # Find all direct child elements.
                child_elements = element.find_elements(By.XPATH, './/*')
                #print(f"element {element.id} has {len(child_elements)}")
                for child in child_elements:
                    dfs(child, level+1)

        dfs(root_element, 0)
        print(collected_texts)
        return collected_texts
    
    def _capture_element_non_info(self, element):
        element_info = {
            "element": element,
            "text": element.get_attribute("text"),
            "resource-id": element.get_attribute("resource-id"),
            "content-desc": element.get_attribute("content-desc"),
            "class": element.get_attribute("class"),
            "bounds": element.get_attribute("bounds"),
            # Collect interaction attributes.
            "clickable": element.get_attribute("clickable"),
            "long-clickable": element.get_attribute("long-clickable"),
            "enabled": element.get_attribute("enabled"),
            "focused": element.get_attribute("focused"),
            # "inputType": element.get_attribute("inputType"),
            "password": element.get_attribute("password")
        }

        # Automatically identify input fields.
        if "edittext" in element_info["class"].lower():
            element_info["is_input"] = 'true'
        else:
            element_info["is_input"] = 'false'
        element_info["generated_xpath"] = self._generate_xpath(element_info, element)
        return element_info
    
    def _capture_element_info(self, element):
        element_info = {
            "element": element,
            "text": element.get_attribute("text"),
            "resource-id": element.get_attribute("resource-id"),
            "content-desc": element.get_attribute("content-desc"),
            "class": element.get_attribute("class"),
            "bounds": element.get_attribute("bounds"),
            # Collect interaction attributes.
            "clickable": element.get_attribute("clickable"),
            "long-clickable": element.get_attribute("long-clickable"),
            "enabled": element.get_attribute("enabled"),
            "focused": element.get_attribute("focused"),
            # "inputType": element.get_attribute("inputType"),
            "password": element.get_attribute("password")
        }
        # Child element text.
        element_info["child_info"] = str(self.traverse_element_and_collect_text(element))

        # Automatically identify input fields.
        if "edittext" in element_info["class"].lower():
            element_info["is_input"] = 'true'
        else:
            element_info["is_input"] = 'false'
        element_info["generated_xpath"] = self._generate_xpath(element_info, element)
        return element_info

    def _get_element_index(self, class_name, target_element):
        try:
            siblings = self.driver.find_elements(AppiumBy.CLASS_NAME, class_name)
            target_id = target_element.id
            for idx, element in enumerate(siblings, 1):
                if element.id == target_id:
                    return idx
            return 1
        except Exception as e:
            print(f"Index calculation failed: {str(e)}")
            return 1

    def _generate_description(self, element_info):
        if "text" in element_info and element_info["text"]:
            return f"Click {element_info['text']}"
        elif "resource-id" in element_info and element_info["resource-id"]:
            return f"Click {element_info['resource-id'].split('/')[-1]}"
        else:
            return "Wait or unknown operation"

    def _save_config(self, filepath='operation_flow_config.json'):
        """
        Save config to a JSON file.
        :param filepath: File path to save.
        """
        def default_to_regular(d):
            if isinstance(d, defaultdict):
                d = {k: default_to_regular(v) for k, v in d.items()}
            return d

        try:
            config = default_to_regular(self.json_config)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            print(f"✅ Config saved to: {filepath}")
            return True
        except Exception as e:
            print(f"❌ Failed to save config: {str(e)}")
            return False

    def process_json_string(self, original_json: str) -> json:
        print(f"origin json {original_json}")
        original_json=original_json.replace("{{","{")
        original_json=original_json.replace("}}","}")
        print(f"fix json {original_json}")

        if original_json.count("{") > 1 :
            idx = original_json.find("}")
            original_json = original_json[:idx + 1]

        try:
            # Check whether "reason" exists in the string.
            if "reason" in original_json:
                index = original_json.index("\"reason\"")  # Find the start position of "reason".
                if index > 0 and original_json[index - 1] != '\n':  # Check whether the previous character is not a newline.
                    # Insert a newline before "reason".
                    original_json = original_json[:index] + '\n' + original_json[index : ]
            if "xpath" in original_json:
                index = original_json.index("\"xpath\"")  # Find the start position of "xpath".
                if index > 0 and original_json[index - 1] != '\n':  # Check whether the previous character is not a newline.
                    # Insert a newline before "xpath".
                    original_json = original_json[:index] + '\n' + original_json[index : ]
            if "action_type" in original_json:
                index = original_json.index("\"action_type\"")  # Find the start position of "action_type".
                if index > 0 and original_json[index - 1] != '\n':  # Check whether the previous character is not a newline.
                    # Insert a newline before "action_type".
                    original_json = original_json[:index] + '\n' + original_json[index : ]
            if "input_text" in original_json:
                index = original_json.index("\"input_text\"")  # Find the start position of "input_text".
                if index > 0 and original_json[index - 1] != '\n':  # Check whether the previous character is not a newline.
                    # Insert a newline before "input_text".
                    original_json = original_json[:index] + '\n' + original_json[index : ]
            if "expected_outcome" in original_json:
                index = original_json.index("\"expected_outcome\"")  # Find the start position of "expected_outcome".
                if index > 0 and original_json[index - 1] != '\n':  # Check whether the previous character is not a newline.
                    # Insert a newline before "expected_outcome".
                    original_json = original_json[:index] + '\n' + original_json[index:]
            if "wait_time" in original_json:
                index = original_json.index("\"wait_time\"")  # Find the start position of "wait_time".
                if index > 0 and original_json[index - 1] != '\n':  # Check whether the previous character is not a newline.
                    # Insert a newline before "wait_time".
                    original_json = original_json[:index] + '\n' + original_json[index:]
            if "}" in original_json:
                index = original_json.index("}")  # Find the start position of "}".
                if index > 0 and original_json[index - 1] != '\n':  # Check whether the previous character is not a newline.
                    # Insert a newline before "}".
                    original_json = original_json[:index] + '\n' + original_json[index:]

            def process_line(line):
                # Process each line.
                quote_positions = []
                for i, char in enumerate(line):
                    if char == '"':
                        quote_positions.append(i)
                # Walk through each quote position and decide whether it needs escaping.
                new_line = []
                for i, char in enumerate(line):
                    if char == '"':
                        # Decide whether this quote needs escaping.
                        pos_index = quote_positions.index(i)
                        total_quotes = len(quote_positions)
                        if not (pos_index in [0, 1, 2] or pos_index == total_quotes - 1):
                            # Needs escaping.
                            new_line.append('\\')
                    if char == '\\':
                        # Skip escape characters.
                        continue
                    new_line.append(char)
                return ''.join(new_line)

            # Split into multiple lines.
            lines = original_json.split('\n')

            # Process each line.
            processed_lines = []
            for line in lines:
                processed_line = process_line(line.strip())
                processed_lines.append(processed_line)

            # Join the processed lines.
            processed_json = '\n'.join(processed_lines)
            print(f"processed_json: {processed_json}")
            result = json.loads(processed_json)
            # print(processed_json)
        except Exception as e:
            print(f"Failed to generate JSON-formatted data: {str(e)}")
            traceback.print_exc()
            return {}
        return result

    def execute_shared_operation(self, operation_type: str, params: dict):
        """Execute an operation that requires cross-device coordination."""
        # Record collaborative operation context.
        context = {
            "operation": operation_type,
            "timestamp": time.time(),
            "source_device": self.json_config["device_id"]
        }

        # Special handling for device sharing flow.
        if operation_type == "device_sharing":
            return self._handle_device_sharing(params)

        # Store context in shared storage.
        if hasattr(self, "multi_device_manager"):
            self.multi_device_manager.shared_data.update(context)

    def _handle_device_sharing(self, params: dict):
        """Handle special device-sharing logic."""
        # Execute local invitation operation.
        self.execute_user_operation(f"邀请{params['target_phone']}加入家庭")

        # Generate collaborative operation instruction.
        return {
            "trigger_operation": "accept_sharing",
            "target_user": params["target_user"],
            "expire_time": time.time() + 300  # Valid for 5 minutes.
        }

    def execute_adb_shell_command(self, shell_command, root=False, is_shell=True):
        try:
            if is_shell:
                adb_command_list = ["adb", "-s", self.UDID, "shell", f'"{shell_command}"'] if not root \
                    else ["adb", "-s", self.UDID, "shell", "su", "-c", f'"{shell_command}"']
            else:
                adb_command_list = ["adb", "-s", self.UDID, shell_command]
            output = subprocess.check_output(" ".join(adb_command_list), shell=True, stderr=subprocess.DEVNULL)
            return output.decode("utf-8")
        except Exception as e:
            mlog.log_func(mlog.ERROR, f"Error executing adb shell command: {e}")
            return None

    def execute_adb_command(self, adb_command):
        try:
            adb_command_list = ["adb", "-s", self.UDID, f'"{adb_command}"']
            output = subprocess.check_output(" ".join(adb_command_list), shell=True, stderr=subprocess.DEVNULL)
            return output.decode("utf-8")
        except Exception as e:
            mlog.log_func(mlog.ERROR, f"Error executing adb shell command: {e}")
            return None

    def find_most_similar(self, filtered_xpath, decision_xpath):
        """
        Find the string in filtered_xpath that is closest to decision_xpath.

        Args:
            filtered_xpath (list): List of strings.
            decision_xpath (str): Target string.

        Returns:
            str: Closest string to decision_xpath.
        """
        if not filtered_xpath:  # Return None directly if the list is empty.
            return None

        # Use SequenceMatcher to calculate similarity.
        def similarity(s1, s2):
            return difflib.SequenceMatcher(None, s1, s2).ratio()

        # Initialize the most similar string and highest similarity.
        most_similar = filtered_xpath[0]
        highest_similarity = similarity(most_similar, decision_xpath)

        # Walk through the list to find the most similar string.
        for xpath in filtered_xpath:
            current_similarity = similarity(xpath, decision_xpath)
            if current_similarity > highest_similarity:
                highest_similarity = current_similarity
                most_similar = xpath

        return most_similar

    def _capture_screenshot(self, filename: str) -> str:
        """Capture the current screen and save it."""
        try:
            # Ensure the filename is not empty.
            if not filename:
                # Create a default filename using the timestamp.
                timestamp = int(time.time())
                filename = f"screenshot_{timestamp}.png"
                print(f"No filename provided. Using default name: {filename}")
            
            # Ensure the filename has an extension.
            if not os.path.splitext(filename)[1]:
                filename = f"{filename}.png"
            
            # If this is a file path, get its directory path first.
            dir_path = os.path.dirname(filename)
            
            # If the directory path is empty, use the screenshots folder in the current directory.
            if not dir_path:
                dir_path = "screenshots"
                filename = os.path.join(dir_path, filename)
            
            # Check whether the directory exists and create it if needed.
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
                print(f"Directory created: {dir_path}")
            else:
                print(f"Directory already exists: {dir_path}")
                
            # Build the full file path.
            filepath = os.path.join(os.getcwd(), filename)
            
            # Ensure the driver has been initialized.
            if self.driver is None:
                print("Screenshot failed: WebDriver is not initialized")
                return ""
                
            # Save screenshot.
            self.driver.save_screenshot(filepath)
            print(f"Screenshot saved: {filepath}")
            return filepath
        except Exception as e:
            print(f"Screenshot failed: {str(e)}")
            traceback.print_exc()
            return ""
    def compare_last_line_with_previous(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()
            
            if len(lines) < 2:
                # Return False directly if the file has fewer than two lines.
                return False
            
            last_line = lines[-1].strip()  # Get the last line and strip leading/trailing whitespace.
            
            # Check previous lines for content identical to the last line.
            for line in lines[:-1]:
                if line.strip() == last_line:
                    return True
            
            return False
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return False
        except Exception as e:
            print(f"Error occurred: {e}")
            return False

    def _evaluate_page_goal_alignment(self, operation_type: str, operation_detail: str) -> dict:
        """
        Evaluate whether the current page matches the user's task goal.
        Returns a dictionary with match status and recommended action.
        
        Args:
            operation_type: Operation type, such as "添加设备".
        """
        try:
            # Get the current page signature.
            current_signature = self._get_state_signature()
            print(f"Current page signature: {current_signature[:20]}...")
            print(f"Saved page signature: {self.current_page_signature[:20] if self.current_page_signature else 'None'}...")
            
            # Use the new method to get all page elements.
            print("⭐ Getting full page information for evaluation...")
            all_page_elements = self._get_all_page_elements()
            print(f"Retrieved full page element count: {len(all_page_elements)}")
            
            # Update page signature.
            self.current_page_signature = current_signature
            self.is_current_page_explored = True
            
            # Build page element information.
            element_info_str = self._build_element_context(all_page_elements)
            
            # Build evaluation prompt.
            eval_prompt_content = f"""You are a professional page evaluation expert. Analyze whether the current page matches the user's task goal.

[Task Goal]
{operation_type}-{operation_detail}

[Current Page Elements]
{element_info_str}

[Evaluation Requirements]
1. Analyze the main function and interactable elements of the current page.
2. Decide whether the current page is related to the task goal.
3. If related, identify which elements can be used to achieve the task goal.
4. If unrelated, explain the difference between the page and the goal, and whether to go back or find another path.
5. "confidence" must be 0.0-1.0, where 0.0 means completely mismatched and 1.0 means completely matched.

[Output Format]
{{
  "page_matches_goal": true/false, 
  "confidence": 0.0-1.0, 
  "reason": "Detailed explanation of whether the page matches the task goal",
  "recommended_action": "continue/go back"
}}"""
            
            # Call the evaluation model.
            chat = ChatZhipuAI(model="glm-4-plus", temperature=0.1, top_p=0.7, max_tokens=1000)
            messages = [
                SystemMessage(content=eval_prompt_content),
                HumanMessage(content=f"Evaluate whether this page matches task '{operation_type}-{operation_detail}'.")
            ]
            
            response = chat.invoke(messages)
            
            try:
                # Parse response.
                evaluation = self.process_json_string(response.content)
                
                # Validate the evaluation result format.
                if isinstance(evaluation, dict) and "page_matches_goal" in evaluation:
                    return evaluation
                else:
                    print("Invalid evaluation result format")
                    # Return safe defaults.
                    return {
                        "page_matches_goal": True,  # Assume the page matches by default to avoid unnecessary recovery.
                        "confidence": 0.5,
                        "reason": "Unable to parse model response",
                        "recommended_action": "continue"
                    }
            except Exception as e:
                print(f"Exception while parsing evaluation response: {str(e)}")
                # Return safe defaults.
                return {
                    "page_matches_goal": False,
                    "confidence": 0.5,
                    "reason": f"Parsing exception: {str(e)}",
                    "recommended_action": "go back"
                }
        
        except Exception as e:
            print(f"Page evaluation exception: {str(e)}")
            traceback.print_exc()
            # Return conservative defaults on error.
            return {
                "page_matches_goal": True,  # Assume the page matches by default to avoid unnecessary recovery.
                "confidence": 0.3,  # Low confidence.
                "reason": f"Evaluation process error: {str(e)}",
                "recommended_action": "continue"
            }
            
    def _record_decision_error(self, operation_type: str, page_evaluation: dict, last_decision: dict = None):
        """
        Record a decision error and provide it to the decision model for improvement.
        
        Args:
            operation_type: Operation type, such as "添加设备".
            page_evaluation: Page evaluation result.
            last_decision: Last decision made, optional.
        """
        try:
            # Build decision-error information.
            error_info = {
                "error_type": "Wrong decision",
                "operation_type": operation_type,
                "timestamp": time.time(),
                "page_evaluation": page_evaluation,
                "previous_decision": last_decision or {},
                "current_state": self._get_state_signature(),
                "recovery_action": page_evaluation.get("recommended_action", "go back")
            }
            
            # Record in feedback.
            self.execution_feedback.append({
                "action": "decision_error_evaluation",
                "success": False,
                "timestamp": time.time(),
                "reason": page_evaluation.get("reason", "Page does not match task goal"),
                "error_details": error_info
            })
            
            # Add detailed error analysis to reflection records.
            error_analysis = f"Decision error analysis: while executing '{operation_type}', the wrong navigation path was selected."
            
            if last_decision and "reason" in last_decision:
                error_analysis += f" Wrong decision reason: '{last_decision['reason']}'."
                
            error_analysis += f" Evaluation result: {page_evaluation.get('reason', 'no reason provided')}."
            error_analysis += f" Suggested improvement: for similar cases, explore all interactable controls before deciding."
            
            self._add_reflection(error_analysis)
            
            print(f"📝 Recorded decision error: {error_analysis}")
            
            return error_info
            
        except Exception as e:
            print(f"Exception while recording decision error: {str(e)}")
            return None

    def _recover_from_wrong_decision(self) -> bool:
        """
        Recover from a wrong-decision state.
        Returns whether recovery succeeded.
        """
        try:
            print("🔄 Trying to recover from a wrong decision...")
            
            # Record the number of operation steps before recovery.
            original_steps_count = 0
            if self.operation_flow:
                original_steps_count = len(self.operation_flow)
            
            # Record the state signature before recovery.
            pre_recovery_state = self._get_state_signature()
            
            # Record current page source for later recovery comparison.
            try:
                pre_recovery_page_source = self.driver.page_source
            except:
                pre_recovery_page_source = ""
            
            # Strategy 1: go back to the previous page.
            print("Strategy 1: trying to go back to the previous page")
            original_state = self._get_state_signature()
            
            # Execute back operation.
            self.driver.back()
            time.sleep(1.5)  # Wait for page to stabilize.
            
            # Check whether state changed.
            new_state = self._get_state_signature()
            if not self.is_similar_state(original_state, new_state, threshold=self.similar_threshold):
                print("✅ Successfully returned to the previous page")
                
                # Record in operation feedback.
                self.execution_feedback.append({
                    "action": "go_back",
                    "success": True,
                    "timestamp": time.time(),
                    "reason": "Recovered from wrong-decision state",
                    "recovery_context": {
                        "pre_recovery_state": pre_recovery_state,
                        "post_recovery_state": new_state
                    }
                })
                
                # Record this recovery operation.
                self._add_reflection("Effective recovery strategy from wrong-decision state: go back to the previous page")
                
                # Recovery succeeded; adjust similarity threshold.
                self._adjust_similarity_threshold(is_recovery_successful=True)
                
                # Remove the wrong-decision operation record.
                self._remove_last_operation_record(original_steps_count)
                
                # Clean wrong state records from page_signatures.txt.
                self._clean_error_state_from_signatures_file(pre_recovery_state)
                
                # Capture a screenshot after recovery for records.
                self._capture_screenshot(f"recovery_success_{int(time.time())}.png")
                
                return True
            
            # Strategy 2: try clicking the back button.
            print("Strategy 2: trying to click the back button")
            try:
                # Find possible back buttons using an expanded search range.
                back_buttons = self.driver.find_elements(AppiumBy.XPATH, 
                    '//*[contains(@text, "返回") or contains(@content-desc, "返回") or contains(@content-desc, "back") or contains(@resource-id, "back") or contains(@resource-id, "back_button") or contains(@text, "取消")]')
                
                if back_buttons:
                    original_state = self._get_state_signature()
                    back_buttons[0].click()
                    time.sleep(1.5)
                    
                    # Check whether state changed.
                    new_state = self._get_state_signature()
                    if not self.is_similar_state(original_state, new_state, threshold=self.similar_threshold):
                        print("✅ Successfully clicked back button to recover from wrong decision")
                        
                        # Record in operation feedback.
                        self.execution_feedback.append({
                            "action": "click_back_button",
                            "success": True,
                            "timestamp": time.time(),
                            "reason": "Recovered from wrong-decision state",
                            "recovery_context": {
                                "pre_recovery_state": pre_recovery_state,
                                "post_recovery_state": new_state,
                                "button_text": back_buttons[0].get_attribute("text") or back_buttons[0].get_attribute("content-desc")
                            }
                        })
                        
                        # Record this recovery operation and button information.
                        button_text = back_buttons[0].get_attribute("text") or back_buttons[0].get_attribute("content-desc") or "unknown text"
                        self._add_reflection(f"Effective recovery strategy from wrong-decision state: clicked '{button_text}' button")
                        
                        # Recovery succeeded; adjust similarity threshold.
                        self._adjust_similarity_threshold(is_recovery_successful=True)
                        
                        # Remove the wrong-decision operation record.
                        self._remove_last_operation_record(original_steps_count)
                        
                        # Clean wrong state records from page_signatures.txt.
                        self._clean_error_state_from_signatures_file(pre_recovery_state)
                        
                        # Capture a screenshot after recovery.
                        self._capture_screenshot(f"recovery_button_success_{int(time.time())}.png")
                        
                        return True
            except Exception as e:
                print(f"Failed to click back button: {str(e)}")
            
            # Strategy 3: if the methods above fail, try navigating to the home page.
            print("Strategy 3: trying to navigate to the home page")
            try:
                # Save current state.
                original_state = self._get_state_signature()
                
                # Try navigating to the home page.
                self._navigate_to_homepage()
                time.sleep(1.5)
                
                # Check whether state changed.
                new_state = self._get_state_signature()
                if not self.is_similar_state(original_state, new_state, threshold=self.similar_threshold):
                    print("✅ Successfully navigated to the home page")
                    
                    # Record in operation feedback.
                    self.execution_feedback.append({
                        "action": "navigate_home",
                        "success": True,
                        "timestamp": time.time(),
                        "reason": "Recovered from wrong-decision state",
                        "recovery_context": {
                            "pre_recovery_state": pre_recovery_state,
                            "post_recovery_state": new_state
                        }
                    })
                    
                    # Record this recovery operation.
                    self._add_reflection("Effective recovery strategy from wrong-decision state: navigate to the home page")
                    
                    # Recovery succeeded; adjust similarity threshold.
                    self._adjust_similarity_threshold(is_recovery_successful=True)
                    
                    # Remove the wrong-decision operation record.
                    self._remove_last_operation_record(original_steps_count)
                    
                    # Clean wrong state records from page_signatures.txt.
                    self._clean_error_state_from_signatures_file(pre_recovery_state)
                    
                    # Capture a screenshot after recovery.
                    self._capture_screenshot(f"recovery_home_success_{int(time.time())}.png")
                    
                    return True
            except Exception as e:
                print(f"Failed to navigate to the home page: {str(e)}")
            
            # Strategy 4: try clicking any possible navigation button.
            print("Strategy 4: trying to click a navigation button")
            try:
                # Find possible navigation buttons.
                nav_buttons = self.driver.find_elements(AppiumBy.XPATH, 
                    '//*[contains(@text, "首页") or contains(@content-desc, "首页") or contains(@text, "主页") or contains(@text, "home") or contains(@resource-id, "home")]')
                
                if nav_buttons:
                    original_state = self._get_state_signature()
                    nav_buttons[0].click()
                    time.sleep(1.5)
                    
                    # Check whether state changed.
                    new_state = self._get_state_signature()
                    if not self.is_similar_state(original_state, new_state, threshold=self.similar_threshold):
                        print("✅ Successfully clicked navigation button")
                        
                        # Record in operation feedback.
                        self.execution_feedback.append({
                            "action": "click_navigation_button",
                            "success": True,
                            "timestamp": time.time(),
                            "reason": "Recovered from wrong-decision state",
                            "recovery_context": {
                                "pre_recovery_state": pre_recovery_state,
                                "post_recovery_state": new_state
                            }
                        })
                        
                        # Record this recovery operation.
                        self._add_reflection("Effective recovery strategy from wrong-decision state: click navigation button")
                        
                        # Recovery succeeded; adjust similarity threshold.
                        self._adjust_similarity_threshold(is_recovery_successful=True)
                        
                        # Remove the wrong-decision operation record.
                        self._remove_last_operation_record(original_steps_count)
                        
                        # Clean wrong state records from page_signatures.txt.
                        self._clean_error_state_from_signatures_file(pre_recovery_state)
                        
                        return True
            except Exception as e:
                print(f"Failed to click navigation button: {str(e)}")
            
            print("❌ All recovery strategies failed")
            
            # Recovery failed; adjust similarity threshold.
            self._adjust_similarity_threshold(is_recovery_successful=False)
            
            # Record recovery failure.
            self.execution_feedback.append({
                "action": "recovery_attempt",
                "success": False,
                "timestamp": time.time(),
                "reason": "All recovery strategies failed"
            })
            
            # Capture a screenshot after recovery failure.
            self._capture_screenshot(f"recovery_failed_{int(time.time())}.png")
            
            return False
            
        except Exception as e:
            print(f"Recovery process exception: {str(e)}")
            traceback.print_exc()
            return False
        
    def _remove_last_operation_record(self, original_steps_count):
        """
        Remove the operation record from the last wrong decision.
        
        Args:
            original_steps_count: Number of operation steps before recovery.
        """
        try:
            # 1. Remove wrong operation records from memory.
            if self.operation_flow and len(self.operation_flow) > original_steps_count:
                # Remove all operation records added after recovery started.
                self.operation_flow = self.operation_flow[:original_steps_count]
                print(f"✂️ Removed wrong operation records from memory")
            
            # 2. Find the last operation record written to the config file.
            if self.json_config["createDatabaseActionOrder"]:
                last_action_type = self.json_config["createDatabaseActionOrder"][-1]
                user, scope, operation = last_action_type.split("|")
                
                # Confirm this operation type has records.
                if operation in self.json_config[user][scope]:
                    # Get step count for this operation.
                    steps = self.json_config[user][scope][operation]
                    if steps:
                        # Remove the last step.
                        max_step = max(int(step) for step in steps.keys())
                        if str(max_step) in steps:
                            print(f"✂️ Removed wrong operation record from config: {last_action_type} step {max_step}")
                            del self.json_config[user][scope][operation][str(max_step)]
                            
                            # If this operation has no steps left, remove it from the operation list.
                            if not self.json_config[user][scope][operation]:
                                self.json_config["createDatabaseActionOrder"].pop()
                
                        # Save the updated config.
                        self._save_config(self.save_path)
            
        except Exception as e:
            print(f"Exception while removing wrong operation record: {str(e)}")
            traceback.print_exc()

    def _perform_wait_operation(self, operation_type: str, reason: str, wait_time: int = 30) -> bool:
        """
        Perform a wait operation and check page changes every 6 seconds.
        
        Args:
            operation_type: Operation type, such as "添加设备".
            reason: Reason for waiting.
            wait_time: Maximum wait time in seconds, default 30.
            
        Returns:
            bool: Whether waiting succeeded, either by detecting page changes or completing the wait.
        """
        print(f"Entering wait state: {reason}. Maximum wait time: {wait_time}s")
        
        # Record initial state and time.
        initial_state = self._get_state_signature()
        start_time = time.time()
        interval = 6  # Check every 6 seconds.
        
        # Update operation records using the operation type.
        self._record_operation_step(
            xpath="N/A", 
            operation_type=operation_type,  # Use operation type.
            reason=reason,
            element=None,
            element_info={"type": "wait", "wait_time": wait_time}  # Add actual wait time.
        )
        
        # Capture a screenshot at wait start.
        screenshot_path = self._capture_screenshot(f"wait_start_{int(start_time)}.png")
        print(f"Wait-start screenshot saved: {screenshot_path}")
        
        # Loop and check for page changes.
        elapsed = 0
        while elapsed < wait_time:
            # Wait for the configured interval.
            time.sleep(interval)
            elapsed = time.time() - start_time
            
            # Get current state.
            current_state = self._get_state_signature()
            
            # Check whether the page changed.
            if not self.is_similar_state(current_state, initial_state):
                # Page changed, so wait succeeded.
                print(f"Page change detected during wait state after {elapsed:.1f}s")
                
                # Capture a screenshot after the change.
                screenshot_path = self._capture_screenshot(f"wait_change_{int(time.time())}.png")
                print(f"Post-change screenshot saved: {screenshot_path}")
                
                # Add success feedback.
                self.execution_feedback.append({
                    "action": operation_type,  # Use operation type.
                    "success": True,
                    "timestamp": time.time(),
                    "reason": f"Page change detected during waiting after {elapsed:.1f}s"
                })
                
                # Add reflection.
                self._add_reflection(f"Successfully detected page change while waiting for '{reason}'. Total time: {elapsed:.1f}s")
                
                return True
            
            print(f"Waited {elapsed:.1f}s with no page change. Continuing to wait...")
        
        # Wait timed out.
        print(f"Wait timed out after {wait_time}s with no page change")
        
        # Capture a screenshot after timeout.
        screenshot_path = self._capture_screenshot(f"wait_timeout_{int(time.time())}.png")
        print(f"Post-timeout screenshot saved: {screenshot_path}")
        
        # Add timeout feedback.
        self.execution_feedback.append({
            "action": operation_type,  # Use operation type.
            "success": False,
            "timestamp": time.time(),
            "reason": f"No page change after waiting {wait_time}s; manual action may be needed"
        })
        
        # Add reflection.
        self._add_reflection(f"Waiting for '{reason}' timed out. No page change within {wait_time}s; check device connection status")
        
        return False

    def _clean_error_state_from_signatures_file(self, state):
        """
        Remove wrong state records from page_signatures.txt.
        
        Args:
            state: State to remove.
        """
        try:
            signatures_file = "page_signatures.txt"
            temp_file_path = "temp_signatures.txt"
            
            # Check whether the original file exists.
            if not os.path.exists(signatures_file):
                print(f"{signatures_file} file not found")
                return
                
            # Read original file contents.
            with open(signatures_file, "r", encoding="utf-8") as file:
                lines = file.readlines()
            
            # Create a temporary file for the updated state records.
            with open(temp_file_path, "w", encoding="utf-8") as temp_file:
                for line in lines:
                    if line.strip() != state:
                        temp_file.write(line)
            
            # Use an alternative method: write directly back to the original file instead of renaming.
            with open(signatures_file, "w", encoding="utf-8") as original:
                # Reopen the temporary file and read contents.
                with open(temp_file_path, "r", encoding="utf-8") as temp:
                    content = temp.read()
                # Write to original file.
                original.write(content)
            
            # Try to delete the temporary file.
            try:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
            except Exception as e:
                print(f"Failed to delete temporary file: {str(e)}")
            
            print(f"Removed wrong state records from {signatures_file}")
            
        except FileNotFoundError:
            print(f"page_signatures.txt file not found")
        except PermissionError:
            print(f"Unable to delete or rename file. It may be locked by permissions or another process")
            # Try copying content directly and overwriting the original file.
            try:
                if os.path.exists(temp_file_path):
                    with open(temp_file_path, "r", encoding="utf-8") as temp:
                        content = temp.read()
                    with open(signatures_file, "w", encoding="utf-8") as original:
                        original.write(content)
                    os.remove(temp_file_path)
                    print(f"Successfully updated {signatures_file} using the alternative method")
            except Exception as inner_e:
                print(f"Alternative method failed: {str(inner_e)}")
        except Exception as e:
            print(f"Exception while deleting wrong state records: {str(e)}")
            traceback.print_exc()

    def _ensure_directories_exist(self):
        """Create the required directory structure."""
        try:
            # Create the screenshots directory.
            if not os.path.exists("screenshots"):
                os.makedirs("screenshots", exist_ok=True)
                print("Created screenshots directory")
                
            # If save_path is a file path, ensure its parent directory exists.
            if self.save_path:
                save_dir = os.path.dirname(self.save_path)
                if save_dir and not os.path.exists(save_dir):
                    os.makedirs(save_dir, exist_ok=True)
                    print(f"Created save directory: {save_dir}")
        except Exception as e:
            print(f"Error while creating directory structure: {str(e)}")
            traceback.print_exc()

    def _reset_page_exploration_state(self):
        """Reset page exploration state when the page changes."""
        print(f"⚠️ Resetting page exploration state")
        print(f"  - Previous page signature: {self.current_page_signature[:20] if self.current_page_signature else 'None'}...")
        print(f"  - Previous exploration state: {self.is_current_page_explored}")
        
        self.current_page_signature = None
        self.is_current_page_explored = False
        print("✅ Page exploration state reset")

    def _get_all_page_elements(self):
        """
        Get all elements on the page, not only interactable controls.
        Returns an independent element set without using self.collected_elements.
        """
        all_elements = set()
        all_elements_xpath = set()
        
        # Get all elements on the page.
        all_page_elements = self.driver.find_elements(
            AppiumBy.XPATH,
            '//*'  # Get all elements.
        )
        print(f"Initial count of all page elements: {len(all_page_elements)}")
        
        # Collect all visible elements.
        for el in all_page_elements:
            try:
                # Only filter invisible elements.
                if not self._is_element_visible(el):
                    continue
                
                info = self._capture_element_info(el)
                xpath = info['generated_xpath']
                if xpath not in all_elements_xpath:
                    all_elements_xpath.add(xpath)
                    all_elements.add(el)
            except StaleElementReferenceException:
                continue
        
        print(f"Visible element count after filtering: {len(all_elements)}")
        
        # Explore the page to get all possible elements.
        if self.explore_horizontal:
            directions = ['down', 'up', 'left', 'right']  # Include horizontal directions.
        else:
            directions = ['down', 'up']  # Only include vertical directions.
        
        last_element_count = len(all_elements_xpath)
        retry = 0
        swap_count = {'down': 0, 'up': 0, 'left': 0, 'right': 0}
        
        try:
            # Try at most one exploration round.
            while retry < 1:
                # Swipe once in every direction.
                for direction in directions:
                    original_state = self._get_state_signature()
                    self._swipe_screen(direction)
                    swap_count[direction] += 1
                    
                    # Get new elements after swiping.
                    new_elements = self.driver.find_elements(AppiumBy.XPATH, '//*')
                    for el in new_elements:
                        try:
                            if not self._is_element_visible(el):
                                continue
                            
                            info = self._capture_element_info(el)
                            xpath = info['generated_xpath']
                            if xpath not in all_elements_xpath:
                                all_elements_xpath.add(xpath)
                                all_elements.add(el)
                        except StaleElementReferenceException:
                            continue
                            
                    # If state changed, keep swiping in the same direction.
                    while self._get_state_signature() != original_state:
                        original_state = self._get_state_signature()
                        self._swipe_screen(direction)
                        swap_count[direction] += 1
                        
                        # Get new elements.
                        new_elements = self.driver.find_elements(AppiumBy.XPATH, '//*')
                        for el in new_elements:
                            try:
                                if not self._is_element_visible(el):
                                    continue
                                
                                info = self._capture_element_info(el)
                                xpath = info['generated_xpath']
                                if xpath not in all_elements_xpath:
                                    all_elements_xpath.add(xpath)
                                    all_elements.add(el)
                            except StaleElementReferenceException:
                                continue
                                
                    # Restore the page position.
                    for count_slip in range(swap_count[direction]):
                        if direction == 'down':
                            self._swipe_screen('up')
                        elif direction == 'up':
                            self._swipe_screen('down')
                        elif direction == 'left':
                            self._swipe_screen('right')
                        elif direction == 'right':
                            self._swipe_screen('left')
                
                # Reset swipe counters.
                swap_count = {'down': 0, 'up': 0, 'left': 0, 'right': 0}
                
                # Check whether the element count increased.
                if len(all_elements_xpath) == last_element_count:
                    retry += 1
                    print(f"⭐ No new elements found in this round, retry={retry}")
                else:
                    retry = 0  # Reset the counter after finding new elements.
                    print(f"⭐ Found new elements in this round. Total elements: {len(all_elements_xpath)}")
                
                last_element_count = len(all_elements_xpath)
                
                # Stop early if enough elements have been collected.
                if len(all_elements_xpath) >= 200:
                    print("⭐ Enough elements collected. Ending exploration early")
                    break
        except Exception as e:
            print(f"Page exploration exception: {str(e)}")
            traceback.print_exc()
        finally:
            print(f"⭐ Page exploration fully completed. Collected {len(all_elements)} elements")
        
        return all_elements

    def _get_non_interactable_text_elements(self):
        """
        Get text from non-interactable controls as page-description context.
        
        Returns:
            str: Formatted non-interactable control text information.
        """
        try:
            print("🔍 Starting to get non-interactable page text...")
            start_time = time.time()
            
            # Get all page elements.
            all_elements = self.driver.find_elements(AppiumBy.XPATH, '//*')
            print(f"📊 Total page elements: {len(all_elements)}")
            
            text_elements = []
            non_text_count = 0
            interactable_count = 0
            non_visible_count = 0
            
            for element in all_elements:
                try:
                    # Check whether the element is visible.
                    if not self._is_element_visible(element):
                        non_visible_count += 1
                        continue
                    
                    # Get element attributes.
                    #element_info = self._capture_element_info(element)
                    element_info = self._capture_element_non_info(element)
                    
                    # Focus only on elements with text that are not interactable.
                    is_interactable = (element_info.get('clickable') == 'true' or 
                                       element_info.get('long-clickable') == 'true' or 
                                       "edit" in element_info.get('class', '').lower())
                    
                    if is_interactable:
                        interactable_count += 1
                        continue
                    
                    # Get element text content.
                    text = element_info.get('text', '').strip()
                    content_desc = element_info.get('content-desc', '').strip()
                    
                    # If the element has text and is not interactable.
                    if (text or content_desc):
                        # Prefer text, and fall back to content-desc.
                        display_text = text or content_desc
                        class_name = element_info.get('class', 'unknown type').split('.')[-1]
                        
                        # Record non-interactable text element.
                        text_elements.append({
                            'text': display_text,
                            'class': class_name,
                            'xpath': element_info.get('generated_xpath', '')
                        })
                    else:
                        non_text_count += 1
                except StaleElementReferenceException:
                    continue
                except Exception as e:
                    print(f"Error while processing non-interactable text element: {str(e)}")
            
            # Sort by text length, giving longer text higher priority because it may contain more information.
            text_elements.sort(key=lambda x: len(x['text']), reverse=True)
            
            end_time = time.time()
            print(f"⏱️ Non-interactable text retrieval took: {end_time - start_time:.2f}s")
            print(f"📊 Stats - total elements: {len(all_elements)}, invisible: {non_visible_count}, interactable: {interactable_count}, no text: {non_text_count}, valid text elements: {len(text_elements)}")
            
            # Format text information.
            if text_elements:
                formatted = ["Non-interactable page text information for understanding current page content:"]
                
                # Keep only the top 10 most important text items.
                top_elements = text_elements[:10]
                for idx, info in enumerate(top_elements, 1):
                    formatted.append(f"{idx}. [{info['class']}] {info['text']}")
                
                result = "\n".join(formatted)
                print(f"✅ Retrieved non-interactable page text successfully. Extracted {len(top_elements)} key text items")
                return result
            else:
                print("⚠️ No non-interactable text information found on the page")
                return "No extractable non-interactable page text information"
                
        except Exception as e:
            print(f"❌ Failed to get non-interactable control text information: {str(e)}")
            traceback.print_exc()
            return "Error while getting page text information"

    def _generate_page_signature(self):
        """
        Generate a page structure signature without focusing on concrete element content or counts.
        Used specifically for loop detection and returns a stable page identifier.
        """
        try:
            # Use activity name as the primary feature.
            try:
                current_activity = self.driver.current_activity
                activity_feature = f"A:{current_activity}"
            except:
                activity_feature = "A:unknown"
            
            # Use package name as an extra identifier that should not change with user operations.
            try:
                package_name = self.driver.current_package
                package_feature = f"P:{package_name}"
            except:
                package_feature = "P:unknown"
            
            # Get page source.
            page_source = self.driver.page_source
            
            # Extract major page layout features.
            layout_types = ["LinearLayout", "RelativeLayout", "FrameLayout", 
                           "ConstraintLayout", "RecyclerView", "ListView",
                           "ScrollView", "ViewPager"]
            
            layout_features = []
            for layout in layout_types:
                count = page_source.count(layout)
                if count > 0:
                    # Record only whether a specific layout exists, ignoring concrete count.
                    layout_features.append(layout)
            
            # Extract major UI control type features.
            ui_types = ["Button", "TextView", "ImageView", "EditText", 
                       "CheckBox", "RadioButton", "Switch", "ProgressBar"]
            
            ui_features = []
            for ui_type in ui_types:
                count = page_source.count(ui_type)
                if count > 0:
                    # Roughly classify control types by category, ignoring concrete count.
                    ui_features.append(ui_type)
            
            # Extract fixed page resource-id features that should not change with user operations.
            try:
                # Find elements with resource-id values; these IDs are usually fixed page features.
                fixed_ids = []
                resource_ids = re.findall(r'resource-id="([^"]+)"', page_source)
                
                # Filter out IDs that may change with user operations.
                # Common stable IDs usually include keywords like layout, container, header, footer, and nav.
                stable_id_keywords = ["layout", "container", "header", "footer", "nav", "page", "view", "screen", "fragment"]
                for rid in resource_ids[:10]:  # Limit count to avoid overly long signatures.
                    base_id = rid.split("/")[-1] if "/" in rid else rid
                    for keyword in stable_id_keywords:
                        if keyword in base_id.lower():
                            if base_id not in fixed_ids:
                                fixed_ids.append(base_id)
                                break
                
                if fixed_ids:
                    fixed_ids = sorted(fixed_ids)[:5]  # Use at most five stable IDs.
                    id_feature = f"ID:{'-'.join(fixed_ids)}"
                else:
                    id_feature = "ID:none"
            except:
                id_feature = "ID:error"
            
            # Try to extract page title or major text features.
            try:
                title_elements = self.driver.find_elements(AppiumBy.XPATH, 
                    '//*[@resource-id and contains(@resource-id, "title") and @text]')
                title_texts = []
                for el in title_elements[:1]:  # Use only the first title element.
                    text = el.get_attribute("text")
                    if text:
                        title_texts.append(f"T:{text}")
                if not title_texts:
                    # Try to get broader possible title elements.
                    potential_titles = self.driver.find_elements(AppiumBy.XPATH,
                        '//*[@text and (contains(@resource-id, "title") or contains(@resource-id, "header"))]')
                    for el in potential_titles[:1]:  # Use only the first.
                        text = el.get_attribute("text")
                        if text:
                            title_texts.append(f"T:{text}")
            except:
                title_texts = []
            
            # Try to extract page navigation or bottom-menu features, which usually remain stable.
            try:
                nav_elements = []
                # Find common bottom navigation styles.
                nav_xpaths = [
                    '//*[contains(@resource-id, "navigation") or contains(@resource-id, "bottomNav")]',
                    '//*[contains(@resource-id, "tabBar") or contains(@resource-id, "tab_bar")]',
                    '//*[contains(@resource-id, "footer") or contains(@resource-id, "bottom")]'
                ]
                
                for xpath in nav_xpaths:
                    nav_els = self.driver.find_elements(AppiumBy.XPATH, xpath)
                    if nav_els:
                        # Navigation bar exists; extract features.
                        nav_elements.append("NavBar")
                        # Try to extract the number of navigation items.
                        nav_items = self.driver.find_elements(AppiumBy.XPATH, f"{xpath}//*[@clickable='true']")
                        if nav_items:
                            nav_elements.append(f"Items:{len(nav_items)}")
                        break
                
                nav_feature = f"Nav:{'-'.join(nav_elements)}" if nav_elements else "Nav:none"
            except:
                nav_feature = "Nav:error"
            
            # Extract page hierarchy depth as a stable feature.
            try:
                # Roughly estimate DOM tree depth.
                xml_depth = page_source.count("<")
                depth_feature = f"Depth:{xml_depth//10*10}"  # Round down to the nearest multiple of 10.
            except:
                depth_feature = "Depth:unknown"
            
            # Combine features into a signature.
            features = [activity_feature, package_feature]
            if title_texts:
                features.extend(title_texts)
            features.append(f"L:{'-'.join(sorted(layout_features))}")
            features.append(f"UI:{'-'.join(sorted(ui_features))}")
            features.append(id_feature)
            features.append(nav_feature)
            features.append(depth_feature)
            
            signature = "|".join(features)
            print(f"🔍 Generated page structure signature for loop detection: {signature}")
            return signature
            
        except Exception as e:
            print(f"Exception while generating page structure signature: {str(e)}")
            return f"ERROR_PAGE_SIGNATURE:{time.time()}"
    
    def _check_page_loop(self, page_signatures_history):
        """
        Check page loops without being affected by element count or state changes.
        Only the page structure identifier is considered.
        
        Args:
            page_signatures_history: Page structure signature history list.
            
        Returns:
            bool: Whether a loop was detected.
        """
        # if len(page_signatures_history) < 3:
        #     return False
        
        # Get the current page structure signature.
        current_signature = self._generate_page_signature()
        
        # Check whether the current signature exists in history, excluding the latest records.
        # Use older records to detect loops and avoid false positives caused by element state changes.
        for old_signature in page_signatures_history[:-1]:
            # Use simple string matching for page structure comparison.
            # Do not use is_similar_state here because stricter structure matching is needed,
            # especially for activity name and major layout features.
            if current_signature == old_signature:
                print(f"Page loop detected: current page structure matches a historical page")
                print(f"Current page signature: {current_signature}")
                print(f"Matched historical signature: {old_signature}")
                return True
        
        # Update page signature history.
        if len(page_signatures_history) == 0:
            page_signatures_history.append(current_signature)
            with open("Loop_page_signatures.txt", "a", encoding="utf-8") as f:
                f.write(f"{current_signature}\n")
        elif len(page_signatures_history) >= 1 and current_signature != page_signatures_history[0]:
            page_signatures_history.append(current_signature)
            with open("Loop_page_signatures.txt", "a", encoding="utf-8") as f:
                f.write(f"{current_signature}\n")
        return False


if __name__ == "__main__":
    # Xiaomi test cases.
    user2_scanner_info = {"user": "user2", "scope": "remote"}
    user2_scanner = SmartHomeAppScanner(APP_json_config=xiaomi_config, device_config=xiaomi_phone1,
                                        explore_horizontal=False, save_path="xiaomi_acceptShare.json")
    user_command = {"接受设备共享": '''在消息中心里，同意来自用户的设备共享邀请'''}  # Works.

    user2_scanner.execute_user_operation(user_command, user_info=user2_scanner_info)
    # user1_scanner.execute_user_operation("添加家庭成员，其手机号为'xxxx'", user_info=user1_scanner_info)

    user2_scanner.driver.quit()

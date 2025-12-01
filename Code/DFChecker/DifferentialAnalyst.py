# -*- coding: utf-8 -*-
import json
import os
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, deque, defaultdict
from opcode import opname

from openai import OpenAI

yunwu_base_url = "https://yunwu.ai/v1"

class LLMAssistDFChecker:
    def __init__(self, sel_model_name=""):
        self.LLM_CONFIG = {
            "ds-r1": {
                "api_key": "sk-dac69aaaba9945a8902d476f4b5352e0",
                "base_url": "https://api.deepseek.com/v1",
                "select_model": "deepseek-reasoner"
            },
            "ds-v3": {
                "api_key": "sk-dac69aaaba9945a8902d476f4b5352e0",
                "base_url": "https://api.deepseek.com/v1",
                "select_model": "deepseek-chat"
            },
            "yunwu-ds-r1": {
                "api_key": os.getenv("yunwu_api_key_init"),
                "base_url": yunwu_base_url,
                "select_model": "deepseek-r1"
            },
            "yunwu-ds-v3": {
                "api_key": os.getenv("yunwu_api_key_init"),
                "base_url": yunwu_base_url,
                "select_model": "deepseek-v3"
            },
            "yunwu-gpt-4.1-mini": {
                "api_key": os.getenv("yunwu_api_key_init"),
                "base_url": yunwu_base_url,
                "select_model": "gpt-4.1-mini-2025-04-14"
            },
            "yunwu-gpt-o1": {
                "api_key": os.getenv("yunwu_api_key_init"),
                "base_url": yunwu_base_url,
                "select_model": "o1"
            },
            "yunwu-gpt-o3-mini": {
                "api_key": os.getenv("yunwu_api_key_init"),
                "base_url": yunwu_base_url,
                "select_model": "o3-mini"
            },
            "yunwu-claude-4-thinking": {
                "api_key": os.getenv("yunwu_api_key_init"),
                "base_url": yunwu_base_url,
                "select_model": "claude-sonnet-4-20250514-thinking"
            }
        }
        self.prompt_file_config = {
            "BTB_semantic_analysis": "BTBAnalysis5.txt",
            "BTB_vote": "Vote4.txt",
            "understand_state_prompt": "UnderstandState4-eng.txt",
            "state_vote": "StateVoter1.txt",
            "differential_analysis": "DifferentialAnalysis10-cwe-eng.txt",
            "differential_analysis_vote": "DifferentialAnalysisVoter2.txt",
        }

        if sel_model_name and sel_model_name not in self.LLM_CONFIG:
            print(f"No model, please sel in: {self.LLM_CONFIG.keys()}")
            exit(-1)

        self.current_model = ""
        self.current_provider = ""
        if sel_model_name:
            self.use_model_config = self.LLM_CONFIG[sel_model_name]
            self.current_model = self.use_model_config["select_model"].replace('.', '')
            self.current_provider = sel_model_name

    def get_model(self):
        return list(self.LLM_CONFIG.keys())

    # set LLM model
    def set_model(self, new_model_name):
        if new_model_name not in self.LLM_CONFIG:
            print(f"No model <{new_model_name}>, please sel in: {self.LLM_CONFIG.keys()}")
            exit(-1)

        self.use_model_config = self.LLM_CONFIG[new_model_name]
        self.current_model = self.use_model_config["select_model"].replace('.', '')
        self.current_provider = new_model_name

    # tool functions
    def filter_sublists_by_mode(self, nested_list):
        if not isinstance(nested_list, list) or not all(isinstance(sublist, list) for sublist in nested_list):
            print(not isinstance(nested_list, list))
            for sublist in nested_list:
                print(type(sublist))
                print(sublist)
                print("...")
            print(not all(isinstance(sublist, list) for sublist in nested_list))
            raise ValueError("")
    
        lengths = [len(sublist) for sublist in nested_list]
        if not lengths:
            return []
    
        counter = Counter(lengths)
        max_count = max(counter.values())
        mode_lengths = [length for length, count in counter.items() if count == max_count]
    
        return [sublist for sublist in nested_list if len(sublist) in mode_lengths]

    def extract_json_list(self, text):
        def clean_json_brackets(json_str):
            pattern = r'''
                (["']) 
                \s+
                (\])
                |
                (\[)
                \s+
                (["'])
            '''

            def replace(match):
                if match.group(1) and match.group(2):
                    return match.group(1) + match.group(2)
                elif match.group(3) and match.group(4):
                    return match.group(3) + match.group(4)
                return match.group(0)

            return re.sub(pattern, replace, json_str, flags=re.VERBOSE)

        def repair_json_string(s):
            in_string = False
            escape = False
            result = []

            for char in s:
                if not in_string:
                    result.append(char)
                    if char == '"':
                        in_string = True
                else:
                    if escape:
                        if char == '"':
                            result.append("'")  # 转义双引号 -> 单引号
                        elif char == '\\':
                            result.append('\\')  # 连续转义反斜杠 -> 保留
                        else:
                            result.append('\\')  # 其他转义字符保留反斜杠
                            result.append(char)
                        escape = False  # 重置转义状态
                    elif char == '\\':
                        escape = True  # 检测到转义符，标记下一个字符
                    elif char == '"':
                        result.append("'")  # 普通双引号 -> 单引号
                    else:
                        result.append(char)  # 其他字符直接保留

            result = [x for x in clean_json_brackets("".join(result).replace("\t", "").replace("\n", "")).replace(",['", ',["').replace("'],", '"],')]
            for i in range(len(result)):
                if result[i] == "'" and (result[i+1] == ']' or result[i+1] == '}'):
                    if result[i + 2] == ",":
                        result[i] = '"'

            for i in range(len(result) - 1, 0, -1):
                if result[i] not in ['"', "'"]: continue
                if result[i] == '"':
                    break
                else:
                    result[i] = '"'
                    break

            repaired = ''.join(result)

            return repaired

        pattern = r'\\?\[(?:\s*(?:\\?\[.*?\\?\],?)*\s*)*\\?\]'
        matches = re.findall(pattern, text, re.DOTALL)

        if not matches:
            return None
    
        json_str = matches[-1]
    
        json_str = json_str.strip()
        json_str = re.sub(r",\s*\]", "]", json_str)
        json_str = re.sub(r",\s*\)", ")", json_str)
    
        pattern = re.compile(r'\{[^{}]*}')
        def replace_quotes(match):
            content = match.group(0)
            content = re.sub(r'"([^"]+?)"\s*:', r"'\1':", content)
            content = re.sub(r':\s*"([^"]*?)"', r": '\1'", content)
            return content
        json_str = pattern.sub(replace_quotes, json_str)
        json_str = json_str.replace(r"\[", "[").replace(r"\]", "]").replace('\\"', "'").replace("\\'", "'")

        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            json_str = re.sub(r'(?<=\[|,)\s*\[', '[', json_str)
            json_str = re.sub(r'\]\s*(?=,|\])', ']', json_str)
            json_str = repair_json_string(json_str)
            return json.loads(json_str)

    def extract_fsm_btb_cls(self, fsm_path, exclude_negative=True):
        if not os.path.exists(fsm_path):
            print("[ERROR] No such FSM file, please check")
            return None
    
        result = {}
        with open(fsm_path, "r", encoding="utf8") as file_handle:
            current_fsm_lines = file_handle.readlines()
            for line_index in range(len(current_fsm_lines)):
                if "_CLS_" not in current_fsm_lines[line_index]:
                    continue
                cls_index = int(current_fsm_lines[line_index].split("_CLS_")[-1][:-4]) if "NoResp" not in current_fsm_lines[line_index] else -100
                # if exclude_negative and cls_index < 0:
                #     continue
                action = current_fsm_lines[line_index].split("_CLS_")[0].split()[-1]
                if action not in result:
                    result[action] = []
                if exclude_negative and cls_index < 0:
                    continue
                if cls_index not in result[action]:
                    result[action].append(cls_index)
        return result

    def extract_user_actions_from_model(self, dot_content, user):
        s0_edge_pattern = re.compile(r'^\s*s0\s*->\s*\w+\s*\[label="([^"]*)"\];$')
        actions = set()

        for line in dot_content.splitlines():
            match = s0_edge_pattern.match(line.strip())
            if match:
                label = match.group(1)
                if user.lower() not in label.lower():
                    continue
                action = label.split('/')[0].strip() if '/' in label else label.strip()
                actions.add(action)

        return sorted(actions)

    def extract_state_semantics(self, text):
        pattern = r'^\|(\x20*)(s|S)?(\d+)(\x20*)\|(\x20*)(.+)(\x20*)\|$'
        state_dict = {}

        for line in text.split('\n'):
            if not line.startswith('|') or '-----' in line:
                continue
            match = re.match(pattern, line)
            if match:
                state = f's{match.group(3)}'
                description = match.group(6).strip()
                state_dict[state] = description

        return state_dict

    def remove_think_content(self, text):
        return re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)

    def _load_file_text(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            ret_content = "".join(f.readlines())
        return ret_content

    def load_prompt(self, prompt_type):
        try:
            return self._load_file_text(f"PromptFiles/{self.prompt_file_config[prompt_type]}")
        except KeyError:
            raise ValueError(f"Wrong prompt type: {prompt_type}")
        except FileNotFoundError:
            raise FileNotFoundError(f"No file: {self.prompt_file_config[prompt_type]}")

    # communicate with LLM model and get response
    def get_LLM_response(self, user_content, system_content, save_path="", show_response=False, just_show_response_id=False, return_message_and_response=False):
        messages = [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content}
        ]

        client = OpenAI(
            api_key=self.use_model_config["api_key"],
            base_url=self.use_model_config["base_url"]
        )
        response = client.chat.completions.create(
            model=self.use_model_config['select_model'],
            messages=messages,
            stream=False
        )
        response_content = self.remove_think_content(response.choices[0].message.content).replace(r'\"', "'").replace(r"\\'", "'")

        if show_response:
            if not just_show_response_id:
                print("**"*80)
            print(f"Receive LLM response, id: {response.id}")
            if not just_show_response_id:
                print(response_content)
    
        if save_path:
            with open(save_path, "w", encoding="utf8") as file_handle:
                file_handle.write(response_content)
            print("\n\nSave LLM response in path: ", save_path)

        if show_response and not just_show_response_id:
            print("**"*80)
    
        return response_content if not return_message_and_response else (messages, response)

    def read_json_file_and_get_LLM_response(self, data, save_in_file=False):
        json_file_path = list(data.keys())[0]
        if not data[json_file_path][0]:
            print(f"File <{json_file_path.split('/')[-1]}> no need analyse because no index >= 0")
            return
        print(f"   Reading file: {json_file_path}")

        file_name = json_file_path.split("/")[-1].replace(".json", "")
        user = file_name.split("_")[1]
        channel = file_name.split("_")[0]
        action = file_name.split("_")[-1]

        # traffic_content = f"**Current action**: {user}|{channel}|{action} \n**Traffic**: {data[json_file_path][1]}"
        traffic_list = json.loads(data[json_file_path][1])
        for index in range(len(traffic_list)):
            traffic_list[index] = str(traffic_list[index])
        traffic_content = f'**Current action**: {user}|{channel}|{action} \n**Traffic**: [TRAFFIC_SET: {" TRAFFIC_SET: ".join(traffic_list)}]'

        # load system content (prompt)
        content_prompt = self.load_prompt("BTB_semantic_analysis")
        # print("="*80)
        # print(content_prompt)
        # print(traffic_content)
        # print("="*80)
        # return False

        # execute 5 times
        total_response_contents = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(
                    self.get_LLM_response,
                    user_content = traffic_content,
                    system_content = content_prompt,
                    show_response = False,
                    just_show_response_id = True
                ) for _ in range(5)
            ]
            response_contents = [future.result() for future in as_completed(futures)]
            for index in range(len(response_contents)):
                response_contents[index] = self.extract_json_list(response_contents[index])
                if not response_contents[index]:
                    continue
                total_response_contents.append(response_contents[index])

        total_response_contents = self.filter_sublists_by_mode(total_response_contents)
        merge_response_content = []
        for btb_index in range(len(total_response_contents[0])):
            merge_response_content.append([llm_result[btb_index][0] for llm_result in total_response_contents])
        merge_response_content = json.dumps(merge_response_content).replace('\\"', "'")
        # print("Merge")
        # print(merge_response_content)
        # print("-" * 80)

        # vote
        print(f"   Start voting for action {user}|{channel}|{action}...")
        # load vote prompt
        vote_prompt = self.load_prompt("BTB_vote")
        vote_result = self.get_LLM_response(merge_response_content, vote_prompt, show_response=False)
        vote_result = self.extract_json_list(vote_result)
        print(f"  ✅ Voting successfully for action {user}|{channel}|{action}")

        write_context = [[""] for _ in range(data[json_file_path][0][-1] + 1)]
        for temp_index in range(len(vote_result)):
            write_context[data[json_file_path][0][temp_index]] = vote_result[temp_index]

        if save_in_file:
            result_save_folder = f"Experiments/UnderstandingAbstractSymbols/{json_file_path.split('/')[1].replace('material_', '')}/{file_name}/{self.current_model}/"
            if not os.path.exists(result_save_folder):
                os.makedirs(result_save_folder)
            vote_save_path = f"{result_save_folder}/{file_name}-{self.prompt_file_config['BTB_semantic_analysis'][:-4]}-{self.prompt_file_config['vote'][:-4]}-{int(time.time())}.json"

            # save
            with open(vote_save_path, "w", encoding="utf8") as result_file:
                print("-"*120)
                print(json.dumps(write_context, indent=4))
                print("-"*80)
                print(f"Save vote result in file: {vote_save_path}")
                json.dump(write_context, result_file, indent=4)
                print("-"*120)

        return (file_name, write_context)

    # pre-parse dot files
    def load_dot(self, dot_file_path):
        if not os.path.exists(dot_file_path):
            print(f"[ERROR] No such file, please check path: <{dot_file_path}>")
            exit(-2)
        return self._load_file_text(dot_file_path)

    def extract_edges(self, dot_content, hide_success_reason=True):
        edge_pattern = re.compile(r'^\s*(\w+)\s*->\s*(\w+)\s*\[label="([^"]*)"\];$')

        graph = defaultdict(lambda: defaultdict(list))

        states = set()
        node_pattern = re.compile(r'^\s*(\w+)\s*\[.*label="\w+".*\]\s*;')

        for line in dot_content.splitlines():
            node_match = node_pattern.match(line.strip())
            if node_match:
                state = node_match.group(1)
                if not state.startswith('__'):
                    states.add(state)

            edge_match = edge_pattern.match(line.strip())
            if edge_match:
                src, dest, label = edge_match.groups()
                if not src.startswith('__') and not dest.startswith('__'):
                    label = label.replace("Operation succeeded", "Operation result: Success").replace("Operation success", "Operation result: Success").replace("Operation Success", "Operation result: Success")
                    if hide_success_reason and "Operation result: Success" in label:
                        label = label[:label.index("Operation result: Success") + len("Operation result: Success") + 1]
                    graph[src][dest].append(label)

        result = {}
        for state in states:
            result.setdefault(state, {})

        # merge label
        for src, dests in graph.items():
            merged_edges = {}
            for dest, labels in dests.items():
                reason_action_dict = {}
                for label in labels:
                    parts = label.split(' / ', 1)
                    if parts[1] not in reason_action_dict:
                        reason_action_dict[parts[1]] = f"{parts[0]}"
                    else:
                        reason_action_dict[parts[1]] += f",{parts[0]}"
                merged_label = [f"{action} / {result}" for result, action in reason_action_dict.items() if "NoElement" not in result and "N/A" not in result]

                # events = []
                # actions = []
                # for label in labels:
                #     parts = label.split(' / ', 1)
                #     if len(parts) == 2:
                #         events.append(parts[0])
                #         actions.append(parts[1])
                #     else:
                #         events.append(label)
                #         actions.append("")
                #
                # merged_event = ",".join(events)
                #
                # unique_actions = set(actions)
                # if len(unique_actions) == 1:
                #     merged_action = next(iter(unique_actions))
                # else:
                #     merged_action = ",".join(actions)
                #
                # merged_label = f"{merged_event} / {merged_action}" if merged_action else merged_event

                if merged_label:
                    merged_edges[dest] = merged_label

            result[src] = merged_edges

        # sort
        sorted_items = sorted(result.items(), key=lambda x: int(x[0][1:]))
        sorted_dict = {k: v for k, v in sorted_items}

        return sorted_dict

    def extract_transitions_by_action(self, dot_content):
        edge_pattern = re.compile(r'^\s*(\w+)\s*->\s*(\w+)\s*\[label="([^"]*)"\];$')
        transitions = defaultdict(list)

        for line in dot_content.splitlines():
            match = edge_pattern.match(line.strip())
            if match:
                src, dest, label = match.groups()
                if src.startswith('__') or dest.startswith('__'):
                    continue

                if ' / ' in label:
                    event, description = label.split(' / ', 1)
                else:
                    event = label
                    description = ""

                if "NoElement" not in description and "N/A" not in description:
                    description = description.replace("Operation succeeded", "Operation result: Success").replace("Operation success", "Operation result: Success").replace("Operation Success", "Operation result: Success")
                    # delete reason of success (do not car)
                    if "Operation result: Success" in description:
                        description = "Operation result: Success."
                    transitions[event.strip()].append([src, description, dest])

        return dict(transitions)

    def parse_dot(self, dot_str):
        graph = {}
        edge_pattern = r'(\w+)\s*->\s*(\w+)\s*\[label="(.*?)"\]'

        for line in dot_str.split('\n'):
            if '->' in line and 'label=' in line:
                match = re.search(edge_pattern, line)
                if match:
                    src, dest, label = match.groups()
                    if src not in ['__start0'] and dest not in ['__start0']:
                        if src not in graph:
                            graph[src] = []
                        graph[src].append((dest, label))

        states = set()
        for line in dot_str.split('\n'):
            if 'shape="circle"' in line:
                match = re.search(r'(\w+)\s*\[', line)
                if match:
                    state = match.group(1)
                    states.add(state)
                    if state not in graph:
                        graph[state] = []

        return graph, states

    def is_error_state(self, state, graph):
        """检查状态是否为错误状态"""
        # 检查所有出边的响应是否为"NoElement"
        for _, label in graph[state]:
            parts = label.split(' / ')
            if len(parts) < 2 or parts[1] != "NoElement":
                return False
        return True

    def find_shortest_paths(self, graph, all_states, start="s0", hide_success_reason=True, show=False):
        # init
        dist = {node: float('inf') for node in graph}
        prev = {node: None for node in graph}
        queue = deque()

        # set start state
        dist[start] = 0
        queue.append(start)

        # BFS
        while queue:
            current = queue.popleft()
            for neighbor, label in graph[current]:
                if dist[neighbor] == float('inf'):
                    dist[neighbor] = dist[current] + 1
                    prev[neighbor] = (current, label)
                    queue.append(neighbor)

        paths = {}
        # initial state
        paths["s0"] = "Initial state"

        for node in graph:
            if node == start:
                continue

            path = []
            current = node
            while prev.get(current) is not None:
                _, label = prev[current]
                label = label.replace("Operation succeeded", "Operation result: Success")
                if hide_success_reason and "Operation result: Success" in label:
                    # label = label[:label.index("Operation result: Success") + len("Operation result: Success") + 1]
                    label = label.split('/')[0]
                path.append(label)
                current = prev[current][0]
            path.reverse()
            paths[node] = path

        # error_states = set()
        for state in all_states:
            if state != 's0' and graph[state] and self.is_error_state(state, graph):
                # error_states.add(state)
                paths[state] = "Error state"

        if show:
            for state in sorted(all_states):
                print(f"{state}: {paths[state]}")

        return paths

    def merge_BTB_semantic_into_FSM(self, vendor_name, hookable_action, semantic_dict={}, save_folder=""):
        vendor_root_path = f"./material_{vendor_name}/"
        FSM_root_path = f"{vendor_root_path}/FSM/{hookable_action}/"
        # cls_semantic_root_path = f'{vendor_root_path}/traffic_cls_symantic/'
        cls_semantic_root_path = f'Experiments/UnderstandingStates/0BTBResultsForUse/{vendor_name}/'
        result_save_path = f'Experiments/UnderstandingStates/{vendor_name}/{hookable_action}/0FSMs/' if not save_folder else save_folder
        if not os.path.exists(result_save_path):
            os.makedirs(result_save_path)

        cls_semantic_result = {}
        # read semantic files
        if not semantic_dict:
            cls_semantic_files = os.listdir(cls_semantic_root_path)
            for cls_semantic_file in cls_semantic_files:
                if not cls_semantic_file.endswith(".json"):
                    continue
                with open(f"{cls_semantic_root_path}/{cls_semantic_file}", "r", encoding="utf8") as file_handle:
                    user = cls_semantic_file.replace(".json", "").split('_')[1]
                    channel = cls_semantic_file.replace(".json", "").split('_')[0]
                    action = cls_semantic_file.replace(".json", "").split('_')[-1]
                    cls_semantic_result["|".join([user, channel, action])] = json.load(file_handle)
        else:
            for key, value in semantic_dict.items():
                user = key.split('_')[1]
                channel = key.split('_')[0]
                action = key.split('_')[-1]
                cls_semantic_result["|".join([user, channel, action])] = value

        # read fsm and merge
        fsm_files = [x for x in os.listdir(FSM_root_path) if "_sym" not in x and "_sem" not in x and x.endswith(".dot")]
        for fsm_file in fsm_files:
            with open(f"{FSM_root_path}/{fsm_file}", "r", encoding="utf8") as file_handle:
                current_fsm_lines = file_handle.readlines()

            # copy to destination
            with open(f"{result_save_path}/{fsm_file}", "w", encoding="utf8") as file_handle:
                file_handle.writelines(current_fsm_lines)

            for line_index in range(len(current_fsm_lines)):
                if "statefuzzing" in fsm_file and '[shape="circle" label="s' in current_fsm_lines[line_index]:
                    continue

                if "_CLS_" not in current_fsm_lines[line_index]:
                    continue
                cls_index = int(current_fsm_lines[line_index].split("_CLS_")[-1][:-4]) if "NoResp" not in current_fsm_lines[line_index] else -100
                action = current_fsm_lines[line_index].split("_CLS_")[0].split()[-1]
                prefix = " ".join(current_fsm_lines[line_index].split("_CLS_")[0].split()[:-1])
                suffix = '"];'

                # replace index -- symantic
                if cls_index == -1:
                    current_fsm_lines[line_index] = f"\t{prefix} Symbol: CLS_-1. Operation result: Success.{suffix}\n"
                elif cls_index == -100:
                    current_fsm_lines[line_index] = f"\t{prefix} Symbol: CLS_NoResponse. Operation result: Failed. Reason: response is empty{suffix}\n"
                elif action not in cls_semantic_result or not cls_semantic_result[action]:
                    continue
                elif cls_index >= len(cls_semantic_result[action]):
                    print(f"Some action's response disappear: <{action}_CLS_{cls_index}> in model <{fsm_file}> in line <{line_index+1}>")
                    continue
                else:
                    current_fsm_lines[line_index] = f"\t{prefix} Symbol: CLS_{cls_index}. {cls_semantic_result[action][cls_index][0]}{suffix}\n"


            with open(f"{result_save_path}/{fsm_file[:-4]}_sem.dot", "w", encoding="utf8") as file_handle:
                file_handle.writelines(current_fsm_lines)

    # main functions of difference analysis
    def understand_BTB(self, vendor_name, test_cls_files_list=[], just_check_exist_cls=True):
        output_sentence = f"{'='*80}\n{time.asctime()} [Notice] Start understanding BTBs' semantic\n{'='*80}"
        # width = len(output_sentence) + 4
        # print('+' + '-' * (width-2) + '+')
        # print('+' + '-' * (width-2) + '+')
        # print('| ' + output_sentence.center(width-4) + ' |')
        # print('+' + '-' * (width-2) + '+')
        # print('+' + '-' * (width-2) + '+')

        root_folder = f"./material_{vendor_name}/"
        fsm_root_folder = f"{root_folder}/FSM/"
        json_files_folder = f"{root_folder}/json/"

        all_cls_files = test_cls_files_list if test_cls_files_list else [x for x in os.listdir(json_files_folder) if not os.path.isdir(x) and x.lower().endswith(".json")]

        print("   All actions: ", all_cls_files)
        print("="*80)

        # extract btb index
        all_fsm_path = []
        for folder in [x for x in os.listdir(fsm_root_folder) if os.path.isdir(f"{fsm_root_folder}/{x}")]:
            all_fsm_path.extend([f"{fsm_root_folder}/{folder}/{x}" for x in os.listdir(f"{fsm_root_folder}/{folder}") if x.lower().endswith(".dot") and "_sym" not in x])

        all_btb_index_dict = {}
        for fsm_path in all_fsm_path:
            cur_btb_dict = self.extract_fsm_btb_cls(fsm_path)
            for key in cur_btb_dict:
                if key not in all_btb_index_dict:
                    all_btb_index_dict[key] = []
                for value in cur_btb_dict[key]:
                    if value not in all_btb_index_dict[key]:
                        all_btb_index_dict[key].append(value)
                all_btb_index_dict[key] = sorted(all_btb_index_dict[key])
        print("   All BTB-cls appeared in model:")
        print(all_btb_index_dict)
        print("="*80)

        need_analyse_list = []
        BTB_semantic_result_dict = {}
        for file in all_cls_files:
            user = file[:-5].split("_")[1]
            channel = file[:-5].split("_")[0]
            action = file[:-5].split("_")[-1]
            json_file_path = f"{json_files_folder}{file}"
            if not os.path.exists(json_file_path):
                print(f"[ERROR] No such file: {json_file_path}")
                continue

            result_dict = {json_file_path:[]}
            BTB_semantic_result_dict[file.replace(".json", "")] = None

            with open(json_file_path, "r", encoding="utf8") as file_handle:
                traffic_content = json.load(file_handle)
                read_index_list = all_btb_index_dict[f"{user}|{channel}|{action}"]
                result_dict[json_file_path].append(read_index_list)
                if not read_index_list:
                    print("[Notice] No BTB need be understand")
                    continue
                if max(read_index_list) >= len(traffic_content):
                    print(f"[ERROR] Some BTB cls data are missing. Please check: {json_file_path}")
                    if not just_check_exist_cls:
                        continue
                    read_index_list = [x for x in read_index_list if x < len(traffic_content)]
                btb_list = [traffic_content[index] for index in read_index_list]
                result_dict[json_file_path].append(json.dumps(btb_list))
            need_analyse_list.append(result_dict)

        if not need_analyse_list:
            print("[Notice] No BTB need be understand")
            return False

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.read_json_file_and_get_LLM_response, data) for data in need_analyse_list]

        for future in as_completed(futures):
            try:
                BTB_result = future.result()
                BTB_semantic_result_dict[BTB_result[0]] = BTB_result[1]
            except Exception as e:
                print(f"Task failed: {e}")

        return BTB_semantic_result_dict

    def understand_states(self, vendor_name, hookable_action, show_content=False, save_file=True, result_save_path="", dot_folder=""):
        vendor_save_path = f'Experiments/UnderstandingStates/{vendor_name}/{hookable_action}/{self.current_model}/' if not result_save_path else result_save_path
        if not os.path.exists(vendor_save_path):
            os.makedirs(vendor_save_path)
        report_save_path = f"{vendor_save_path}/{self.current_provider}-{self.prompt_file_config['understand_state_prompt'][:-4]}-{self.prompt_file_config['state_vote'][:-4]}-{int(time.time())}.md"

        understand_result = {}

        # create openAI client
        client = OpenAI(
            api_key=self.use_model_config["api_key"],
            base_url=self.use_model_config["base_url"]
        )

        # Analyse base model
        # load prompt
        system_content = self.load_prompt("understand_state_prompt").replace("[Model]", "[Base model]")

        # get state path from dot file
        # dot_data = self.load_dot(f"./material_{vendor_name}/FSM/{hookable_action}/basemodel_sym.dot")
        read_dot_folder = dot_folder if dot_folder else f"Experiments/UnderstandingStates/{vendor_name}/{hookable_action}/0FSMs/"
        dot_data = self.load_dot(f"{read_dot_folder}/basemodel_sem.dot")
        graph, ret_all_states = self.parse_dot(dot_data)
        paths = self.find_shortest_paths(graph, ret_all_states)

        # tell LLM user1's invitation method
        user1_actions = [x for x in self.extract_user_actions_from_model(dot_data, "user1") if
                         x.split("|")[-1].lower().startswith("share") or x.split("|")[-1].lower().startswith("invite")]
        # check length
        if len(user1_actions) != 1:
            print(f"{time.asctime()} [Debug] Please check user1's actions when get invitation method: {user1_actions}.")
            input_result = input("Input 'y' to continue, else quit: ")
            if input_result.lower() != 'y':
                exit(8)
        # tell
        system_content = system_content.replace("[InvitationMethod]",
                                                "[Share device to user2]" if "share" in user1_actions[
                                                    0].lower() else "[Invite user2 to become a family member]")

        # tell LLM user2's accept method
        user2_accept_actions = [x for x in self.extract_user_actions_from_model(dot_data, "user2") if
                                "accept" in x.lower()]
        system_content = system_content.replace("[User2Actions]", "[Need to accept manually]" if len(
            user2_accept_actions) else "[No need to accept manually]")

        user_content = ""
        for key, item in paths.items():
            user_content += f"{key}: {item}\n"

        print(f"  {time.asctime()} [<Base Model> states] Asking LLM ...")

        # get state semantic 5 times
        total_response_contents = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(
                    self.get_LLM_response,
                    user_content=user_content,
                    system_content=system_content,
                    show_response=False,
                    just_show_response_id=True
                ) for _ in range(5)
            ]
            response_contents = [future.result() for future in as_completed(futures)]
            for index in range(len(response_contents)):
                response_contents[index] = self.remove_think_content(response_contents[index])
                if not response_contents[index]:
                    continue
                total_response_contents.append(response_contents[index])

        print(f"  {time.asctime()} ✅ Finish")

        # vote
        state_vote_content = self.load_prompt("state_vote")
        state_vote_content = state_vote_content.replace("[InvitationMethod]",
                                                "[Share device to user2]" if "share" in user1_actions[
                                                    0].lower() else "[Invite user2 to become a family member]")
        state_vote_content = state_vote_content.replace("[User2Actions]", "[Need to accept manually]" if len(
            user2_accept_actions) else "[No need to accept manually]")
        base_semantic_content = "\n\n".join(total_response_contents)
        vote_messages = [
            {"role": "system", "content": state_vote_content},
            {"role": "user", "content": base_semantic_content}
        ]

        print(f"  {time.asctime()} Voting ...")
        response = client.chat.completions.create(
            model=self.use_model_config['select_model'],
            messages=vote_messages,
            stream=False
        )

        # analyse base model states
        response_content = self.remove_think_content(response.choices[0].message.content)
        print(f"  {time.asctime()} ✅ Finish")

        if show_content:
            print("=" * 120)
            print(f"{time.asctime()} [Understanding <Base Model> states' notice] Receive vote response:")
            print(response_content)
            print("=" * 120)

        report_content = f"# Base Model\n{response_content}\n\n"
        understand_result["base_model"] = response_content

        divergent_model_path = f"{read_dot_folder}/statefuzzing_sem.dot"
        if os.path.exists(divergent_model_path):
            # Analyse divergent model
            # get state path from dot file
            dot_data = self.load_dot(divergent_model_path)
            graph, ret_all_states = self.parse_dot(dot_data)
            paths = self.find_shortest_paths(graph, ret_all_states)
            system_content.replace("[Base model]", "[Divergent model]")
            # user_content = "The next model is 'Divergent model'：\n"
            user_content = ""
            for key, item in paths.items():
                user_content += f"{key}: {item}\n"

            print(f"  {time.asctime()} [<Divergent Model> states] Asking LLM ...")

            # get state semantic 5 times
            total_response_contents = []
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(
                        self.get_LLM_response,
                        user_content=user_content,
                        system_content=system_content,
                        show_response=False,
                        just_show_response_id=True
                    ) for _ in range(5)
                ]
                response_contents = [future.result() for future in as_completed(futures)]
                for index in range(len(response_contents)):
                    response_contents[index] = self.remove_think_content(response_contents[index])
                    if not response_contents[index]:
                        continue
                    total_response_contents.append(response_contents[index])

            print(f"  {time.asctime()} ✅ Finish")

            # vote
            # state_vote_content = self.load_prompt("state_vote")
            divergent_semantic_content = "\n\n".join(total_response_contents)
            vote_messages = [
                {"role": "system", "content": state_vote_content},
                {"role": "user", "content": divergent_semantic_content}
            ]

            print(f"  {time.asctime()} Voting ...")
            response = client.chat.completions.create(
                model=self.use_model_config['select_model'],
                messages=vote_messages,
                stream=False
            )

            response_content = self.remove_think_content(response.choices[0].message.content)
            print(f"  {time.asctime()} ✅ Finish")

            if show_content:
                print("=" * 120)
                print(f"{time.asctime()} [Understanding <Divergent Model> states' notice] Receive LLM response:")
                print(response_content)
                print("=" * 120)

            # report_content += f"# Divergent Model\n## Prompt\n```markdown\n{user_content}\n```\n## Result\n{response_content}\n\n"
            report_content += f"# Divergent Model\n{response_content}\n\n"
            understand_result["divergent_model"] = response_content

        if save_file:
            print(f"  {time.asctime()} [Experiment Notice] Report is saved in: <{report_save_path.split('/')[-1]}>")
            print("=" * 80)
            with open(report_save_path, "w", encoding='utf-8') as write_report_handle:
                write_report_handle.write(report_content)

        return understand_result

    def discovering_bugs(self, hookable_action, state_semantic_dict, dot_folder_path):
        # load prompt
        system_content = self.load_prompt("differential_analysis")

        # load state semantic result
        system_content = system_content.replace('[Base model state semantic]', f'[Base model state semantic]\n{state_semantic_dict["base_model"]}')
        system_content = system_content.replace('[Divergent model state semantic]', f'[Divergent model state semantic]\n{state_semantic_dict["divergent_model"]}' if 'divergent_model' in state_semantic_dict else '')

        # load state counts of base model
        dot_data = self.load_dot(f"{dot_folder_path}/basemodel.dot")
        graph, ret_all_states = self.parse_dot(dot_data)
        base_model_max_state = len(ret_all_states) - 1
        system_content = system_content.replace("S[X]",f"S[{base_model_max_state}]").replace("[Hookable Action]", f"[{hookable_action}]")

        if "divergent_model" in state_semantic_dict:
            divergent_model_state_semantic = self.extract_state_semantics(state_semantic_dict["divergent_model"])
            dot_data = self.load_dot(f"{dot_folder_path}/statefuzzing_sem.dot")
            state_edges = self.extract_edges(dot_data)
            for state in state_edges.keys():
                if state in divergent_model_state_semantic:
                    state_edges[state] = [divergent_model_state_semantic[state], state_edges[state]]
            # state_edges = self.extract_transitions_by_action(dot_data)
        else:
            base_model_state_semantic = self.extract_state_semantics(state_semantic_dict['base_model'])
            dot_data = self.load_dot(f"{dot_folder_path}/basemodel_sem.dot")
            state_edges = self.extract_edges(dot_data)
            for state in state_edges.keys():
                if state in base_model_state_semantic:
                    state_edges[state] = [base_model_state_semantic[state], state_edges[state]]
        user_content = f"{json.dumps(state_edges, indent=4, ensure_ascii=False)}"

        print(f"  {time.asctime()} Asking LLM ...")
        # get state semantic 5 times
        total_response_contents = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(
                    self.get_LLM_response,
                    user_content=user_content,
                    system_content=system_content,
                    show_response=False,
                    just_show_response_id=True
                ) for _ in range(5)
            ]
            response_contents = [future.result() for future in as_completed(futures)]
            for index in range(len(response_contents)):
                response_contents[index] = self.remove_think_content(response_contents[index])
                if not response_contents[index]:
                    continue
                total_response_contents.append(response_contents[index])

        # vote
        vote_system_content = self.load_prompt("differential_analysis_vote")
        vote_user_content = ''
        for index in range(len(total_response_contents)):
            vote_user_content += f'---\n**[Report {index+1}]**\n{total_response_contents[index]}\n'

        print(f"  {time.asctime()} Voting ...")
        vote_result = self.get_LLM_response(
            vote_user_content,
            vote_system_content,
            show_response=False,
            just_show_response_id=True
        )
        print("  ✅ Get vote report")
        return vote_result


    def main(self, vendor_name, hookable_action, special_tips="", use_history_BTB_result=True):
        """
        1. understand [Abstract symbols] - vote;
        2. understand [Base model] and [Divergent model] states - vote;
        3. differential analysis - vote
        :param vendor_name:
        :param hookable_action:
        :return:
        """
        title = f'{"*" * 50}  {time.asctime()} [NOTICE] {"*" * 50}'
        print(title)
        print(f"Differential analysis process start!")
        print(f"Current mission: <{vendor_name}> <{hookable_action}> <{self.current_provider}>")
        print("*"*len(title))

        save_root_folder = f"Experiments/0LLMAssistDFResults/{vendor_name}/{hookable_action}/{self.current_model}/"
        FSM_save_folder = f"{save_root_folder}/FSMs/"

        report_content = f"# Tips\n{special_tips}\n\n" if special_tips else special_tips

        print(f"\n{time.asctime()} [Stage 1/3] Processing BTB Semantics...")
        print('-'*60)
        # 1. get BTB semantic
        semantic_save_path = f"{save_root_folder}/BTBUnderstandingResult.json"
        if not os.path.exists(semantic_save_path) or not use_history_BTB_result:
            print(" Generating new BTB semantic analysis...")
            BTB_semantic_dict = self.understand_BTB(vendor_name, just_check_exist_cls=True)
            # save in file
            if not os.path.exists(FSM_save_folder):
                os.makedirs(FSM_save_folder)
            with open(semantic_save_path, "w", encoding="utf8") as file_handle:
                json.dump(BTB_semantic_dict, file_handle, indent=4)
            print(" ✅ BTB semantic saved successfully")
        else:
            print(f"  Loading existing BTB semantic from: {semantic_save_path}")
            with open(semantic_save_path, "r", encoding='utf8') as file_handle:
                BTB_semantic_dict = json.load(file_handle)
            print(" ✅ BTB semantic loaded successfully")
        report_content += f"# BTB Semantic\n```json\n{json.dumps(BTB_semantic_dict, indent=4)}\n```\n\n"

        # merge BTB semantic into models
        print(" Merging BTB semantic into FSM models...")
        self.merge_BTB_semantic_into_FSM(vendor_name, hookable_action, semantic_dict=BTB_semantic_dict, save_folder=FSM_save_folder)

        # 2. Understand state semantic
        print(f"\n{time.asctime()} [Stage 2/3] Understanding state semantics...")
        state_semantic_result = self.understand_states(vendor_name, hookable_action, dot_folder=FSM_save_folder, save_file=False)
        print(" ✅ State semantic analysis completed")
        report_content += f'# State Semantic\n## Base model\n{state_semantic_result["base_model"]}\n\n'
        if "divergent_model" in state_semantic_result:
            report_content += f'## Divergent model\n{state_semantic_result["divergent_model"]}\n\n'

        # 3. Discovering bugs
        print(f"\n{time.asctime()} [Stage 3/3] Discovering bugs...")
        bug_report = self.discovering_bugs(hookable_action, state_semantic_result, FSM_save_folder)
        print(" ✅ Bug discovery completed")
        bug_report = bug_report.replace('### ', '## ')
        report_content += f'# Bug Reports\n{bug_report}'

        # save in file
        report_save_path = f'{save_root_folder}/BugReport-{int(time.time())}.md'
        print(f"\n{time.asctime()} [Report Generation] Saving final report to: {report_save_path}")
        with open(report_save_path, 'w', encoding='utf8') as save_file_handle:
            save_file_handle.write(report_content)
        print(" ✅ Report saved successfully")

        print("\n" + "*" * 50)
        print(f"{time.asctime()} Analysis completed for {vendor_name}/{hookable_action}")
        print("*" * 50 + "\n")

        return True


def understanding_btb_only(test_vendor_list=[], test_model_list=["yunwu-ds-v3", "yunwu-gpt-4.1-mini", "yunwu-gpt-o1", "yunwu-gpt-o3-mini", "yunwu-ds-r1"], test_count=3):
    my_checker = LLMAssistDFChecker()

    # get BTB semantic
    model_list = test_model_list
    vendor_list = [x[9:] for x in os.listdir("./") if "material_" in x] if not test_vendor_list else test_vendor_list

    for vendor in vendor_list:
        action_list = [x.replace(".json", "") for x in os.listdir(f"material_{vendor}/json/")]
        for cur_action in action_list:
            if "AddDevice" in cur_action:
                continue
            result_save_folder = f"Experiments/UnderstandingAbstractSymbols/{vendor}/"
            for model in model_list:
                my_checker.set_model(model)
                cur_folder = f"{result_save_folder}/{cur_action}/{my_checker.current_model}/"
                if not os.path.exists(cur_folder):
                    os.makedirs(cur_folder)
                while len([x for x in os.listdir(cur_folder) if
                           my_checker.prompt_file_config["BTB_semantic_analysis"][:-4] in x and
                           my_checker.prompt_file_config["BTB_vote"][:-4] in x]) < test_count:
                    print(f'[Notice {time.asctime()}] Vendor <{vendor}>, action: <{cur_action}> and model <{model}>, count: <{len([x for x in os.listdir(cur_folder) if my_checker.prompt_file_config["BTB_semantic_analysis"][:-4] in x and my_checker.prompt_file_config["BTB_vote"][:-4] in x])}>')
                    if not my_checker.understand_BTB(vendor, test_cls_files_list=[f"{cur_action}.json"]):
                        print(f"[Notice {time.asctime()}] Vendor <{vendor}>'s action <{cur_action}> with model <{model}> no need analyse!")
                        break
                print(f"[Notice {time.asctime()}] Vendor <{vendor}>'s action <{cur_action}> with model <{model}> finish!")

    print(f"[Notice] End time: {time.asctime()}")
    exit(111)

def understanding_states_only(test_vendor_list=[], test_hookable_action_list=[], test_model_list=[], test_count=3):
    def merge_BTB_semantic_into_FSM(vendor_name, hookable_action):
        vendor_root_path = f"./material_{vendor_name}/"
        FSM_root_path = f"{vendor_root_path}/FSM/{hookable_action}/"
        cls_semantic_root_path = f'Experiments/UnderstandingStates/0BTBResultsForUse/{vendor_name}/'
        result_save_path = f'Experiments/UnderstandingStates/{vendor_name}/{hookable_action}/0FSMs/'
        if not os.path.exists(result_save_path):
            os.makedirs(result_save_path)

        # read semantic files
        cls_semantic_files = os.listdir(cls_semantic_root_path)
        cls_semantic_result = {}
        for cls_semantic_file in cls_semantic_files:
            if not cls_semantic_file.endswith(".json"):
                continue
            with open(f"{cls_semantic_root_path}/{cls_semantic_file}", "r", encoding="utf8") as file_handle:
                user = cls_semantic_file.replace(".json", "").split('_')[1]
                channel = cls_semantic_file.replace(".json", "").split('_')[0]
                action = cls_semantic_file.replace(".json", "").split('_')[-1]
                cls_semantic_result["|".join([user, channel, action])] = json.load(file_handle)

        # read fsm and merge
        fsm_files = [x for x in os.listdir(FSM_root_path) if "_sym" not in x and "_sem" not in x and x.endswith(".dot")]
        for fsm_file in fsm_files:
            with open(f"{FSM_root_path}/{fsm_file}", "r", encoding="utf8") as file_handle:
                current_fsm_lines = file_handle.readlines()

            # copy to destination
            with open(f"{result_save_path}/{fsm_file}", "w", encoding="utf8") as file_handle:
                file_handle.writelines(current_fsm_lines)

            for line_index in range(len(current_fsm_lines)):
                if "statefuzzing" in fsm_file and '[shape="circle" label="s' in current_fsm_lines[line_index]:
                    continue

                if "_CLS_" not in current_fsm_lines[line_index]:
                    continue
                cls_index = int(current_fsm_lines[line_index].split("_CLS_")[-1][:-4]) if "NoResp" not in current_fsm_lines[
                    line_index] else -100
                action = current_fsm_lines[line_index].split("_CLS_")[0].split()[-1]
                prefix = " ".join(current_fsm_lines[line_index].split("_CLS_")[0].split()[:-1])
                suffix = '"];'

                # replace index -- symantic
                if cls_index == -1:
                    current_fsm_lines[line_index] = f"\t{prefix} Symbol: CLS_-1. Operation result: Success.{suffix}\n"
                elif cls_index == -100:
                    current_fsm_lines[line_index] = f"\t{prefix} Symbol: CLS_NoResponse. Operation result: Failed. Reason: response is empty{suffix}\n"
                elif action not in cls_semantic_result or not cls_semantic_result[action]:
                    continue
                elif cls_index >= len(cls_semantic_result[action]):
                    print(f"Some action's response disappear: <{action}_CLS_{cls_index}> in model <{fsm_file}> in line <{line_index+1}>")
                    continue
                else:
                    current_fsm_lines[line_index] = f"\t{prefix} Symbol: CLS_{cls_index}. {cls_semantic_result[action][cls_index][0]}{suffix}\n"

            with open(f"{result_save_path}/{fsm_file[:-4]}_sem.dot", "w", encoding="utf8") as file_handle:
                file_handle.writelines(current_fsm_lines)

    print("*" * 80)
    print(f"{time.asctime()} [Experiment Notice] Mission: Understand states only start!")
    print("*" * 80)

    my_checker = LLMAssistDFChecker()

    model_list = test_model_list if test_model_list else ["yunwu-ds-v3", "yunwu-gpt-4.1-mini", "yunwu-gpt-o1", "yunwu-gpt-o3-mini", "yunwu-ds-r1"]
    vendor_list = [x[9:] for x in os.listdir("./") if "material_" in x] if not test_vendor_list else test_vendor_list

    for vendor in vendor_list:
        action_list = os.listdir(f"material_{vendor}/FSM/") if not test_hookable_action_list else test_hookable_action_list
        all_hookable_action_list = os.listdir(f"material_{vendor}/FSM/")

        for cur_action in action_list:
            if cur_action not in all_hookable_action_list:
                print(f"{time.asctime()} [Error] No such hookable action <{cur_action}> in <{vendor}>")
                continue

            merge_BTB_semantic_into_FSM(vendor, cur_action)
            for model in model_list:
                my_checker.set_model(model)
                cur_folder_path = f"Experiments/UnderstandingStates/{vendor}/{cur_action}/{my_checker.current_model}/"
                if not os.path.exists(cur_folder_path):
                    os.makedirs(cur_folder_path)

                cur_count = len([x for x in os.listdir(cur_folder_path) if
                           my_checker.prompt_file_config["understand_state_prompt"][:-4] in x and
                           my_checker.prompt_file_config["state_vote"][:-4] in x])
                cur_count = len(os.listdir(cur_folder_path))
                while cur_count < test_count:
                    print(f'{time.asctime()} [Notice] Vendor <{vendor}>, action: <{cur_action}> and model <{model}>, count: <{cur_count}>')
                    my_checker.understand_states(vendor, cur_action, show_content=True)
                    # update count
                    cur_count = len([x for x in os.listdir(cur_folder_path) if
                                     my_checker.prompt_file_config["understand_state_prompt"][:-4] in x and
                                     my_checker.prompt_file_config["state_vote"][:-4] in x])
                    cur_count = len(os.listdir(cur_folder_path))

                print(f"{time.asctime()} [Notice] Vendor <{vendor}>'s action <{cur_action}> with model <{model}> finish!")

    print(f"[Notice] End time: {time.asctime()}")
    exit(112)

def discovering_bugs_only(test_vendor_list=[], test_hookable_action_list=[], test_model_list=[], test_count=3):
    my_checker = LLMAssistDFChecker()

    model_list = test_model_list if test_model_list else ["yunwu-ds-v3", "yunwu-gpt-4.1-mini", "yunwu-gpt-o1", "yunwu-gpt-o3-mini", "yunwu-ds-r1"]
    vendor_list = [x[9:] for x in os.listdir("./") if "material_" in x] if not test_vendor_list else test_vendor_list

    for vendor in vendor_list:
        action_list = os.listdir(f"material_{vendor}/FSM/") if not test_hookable_action_list else test_hookable_action_list
        all_hookable_action_list = os.listdir(f"material_{vendor}/FSM/")

        for cur_action in action_list:
            print(cur_action)
            if cur_action not in all_hookable_action_list:
                print(f"{time.asctime()} [Error] No such hookable action <{cur_action}> in <{vendor}>")
                continue
            save_folder = f"Experiments/DiscoveringBugs/{vendor}/{cur_action}/"
            dot_folder = f"{save_folder}/0FSMs/"
            state_semantic_file = f"{save_folder}/state_semantic_result.md"
            # load state semantic result
            if not os.path.exists(state_semantic_file):
                print(f" [ERROR] No state_semantic_result.md for {vendor}/{cur_action}")
                continue

            state_semantic_result = {}
            with open(state_semantic_file, "r", encoding='utf8') as file_handle:
                lines = file_handle.readlines()
                divergent_line_index = None
                for index in range(len(lines) - 1, -1, -1):
                    if "divergent model" in lines[index].lower():
                        state_semantic_result['divergent_model'] = ''.join(lines[index+1:])
                        divergent_line_index = index
                        continue
                    if "base model" in lines[index].lower():
                        state_semantic_result['base_model'] = ''.join(lines[index+1:divergent_line_index])
                        break

            for model in model_list:
                my_checker.set_model(model)

                model_save_folder = f'{save_folder}/{model}'
                if not os.path.exists(model_save_folder):
                    os.makedirs(model_save_folder)
                # while len(os.listdir(model_save_folder)) < test_count:
                for _ in range(test_count):
                    bug_report = my_checker.discovering_bugs(cur_action, state_semantic_result, dot_folder)
                    report_save_path = f'{model_save_folder}/DiscoveringBugsReport-{my_checker.prompt_file_config["differential_analysis"]}-{my_checker.prompt_file_config["differential_analysis_vote"]}-{int(time.time())}.md'
                    print(f"{time.asctime()} [Report Generation] Saving final report to: {report_save_path}")
                    with open(report_save_path, 'w', encoding='utf8') as save_file_handle:
                        save_file_handle.write(bug_report)
                    print(" ✅ Report saved successfully")


def differential_analysis_main(test_vendor_list=[], test_hookable_action_list=[], test_model_list=[], use_history_BTB_result=True):
    my_checker = LLMAssistDFChecker()

    model_list = test_model_list if test_model_list else ["yunwu-ds-r1", "yunwu-ds-v3", "yunwu-gpt-4.1-mini", "yunwu-gpt-o1", "yunwu-gpt-o3-mini"]
    vendor_list = [x[9:] for x in os.listdir("./") if "material_" in x] if not test_vendor_list else test_vendor_list

    for vendor in vendor_list:
        action_list = os.listdir(f"material_{vendor}/FSM/") if not test_hookable_action_list else test_hookable_action_list
        all_hookable_action_list = os.listdir(f"material_{vendor}/FSM/")

        for cur_action in action_list:
            if cur_action not in all_hookable_action_list:
                print(f"{time.asctime()} [Error] No such hookable action <{cur_action}> in <{vendor}>")
                continue

            for model in model_list:
                my_checker.set_model(model)
                my_checker.main(vendor, cur_action, use_history_BTB_result=use_history_BTB_result)


if __name__ == "__main__":
    # understanding_btb_only(test_vendor_list=["xiaomi"], test_count=4)
    # understanding_states_only(test_vendor_list=["xiaomi"])
    discovering_bugs_only(test_vendor_list=["tuya", "xiaomi", "broadlink"], test_hookable_action_list=[], test_model_list=["yunwu-ds-r1"])
    # differential_analysis_main(test_vendor_list=["huawei_lamp", "broadlink", "tuya"])


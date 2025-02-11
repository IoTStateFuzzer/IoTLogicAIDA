import os
import re


def get_file_lines(file_path):
    # file_path = f"{os.path.dirname(__file__)}/{file_path}"
    if not os.path.exists(file_path):
        print("ERROR, file not exist")
        exit(1)
    with open(file_path, "r") as file:
        lines = file.readlines()
    for index in range(len(lines)):
        lines[index] = lines[index].replace("\n", "")
    return lines


def get_prefix_suffix_state_change_lines(file_lines):
    state_change_re = r"s\d+ -> s\d+"
    prefix_list = []
    suffix_list = []
    state_lines = []

    flag = False
    for index in range(len(file_lines)):
        if not re.search(state_change_re, file_lines[index]):
            if not flag:
                prefix_list.append(file_lines[index])
            else:
                suffix_list.append(file_lines[index])
        else:
            flag = True
            state_lines.append(file_lines[index])
    
    return prefix_list, suffix_list, state_lines


def merge_state_condition(state_lines):
    result_dict = {}
    for line in state_lines:
        state_tran = line.split(' [label="')[0]
        request = line.split(' [label="')[-1].split(' / ')[0]
        response = line.split(' [label="')[-1].split(' / ')[-1].split('"')[0]
        fontcolor = None if "fontcolor=" not in line else line.split('fontcolor="')[-1].split('"')[0]
        color = line.split(', color="')[-1].split('"')[0] if ", color=" in line else None

        if state_tran not in result_dict:
            result_dict[state_tran] = {}
        if response not in result_dict[state_tran]:
            result_dict[state_tran][response] = {}
            result_dict[state_tran][response][color] = {}
            result_dict[state_tran][response][color][fontcolor] = []
        
        if request not in result_dict[state_tran][response][color][fontcolor]:
            result_dict[state_tran][response][color][fontcolor].append(request)
    
    merged_lines = []
    for state_tran in result_dict:
        for resp in result_dict[state_tran]:
            for color in result_dict[state_tran][resp]:
                for fontcolor in result_dict[state_tran][resp][color]:
                    merged_lines.append(f'{state_tran} [label="{" ".join(result_dict[state_tran][resp][color][fontcolor])} / {resp}", color="{color}", fontcolor="{fontcolor}"];')
    
    return merged_lines


def get_dot_graph(transition_lines, state_counts):
    if len(transition_lines) % state_counts:
        raise Exception(f"transiton lines can not devide state count: {len(transition_lines)}/{state_counts}")
    
    # graph = [[["", "", "red"] for _ in range(state_counts)] for _ in range(state_counts)]
    graph = [{} for _ in range(state_counts)]

    for line in transition_lines:
        start_state = int(re.search(r"s\d+ -> s\d+", line).group(0).split(" -> ")[0][1:])
        end_state = int(re.search(r"s\d+ -> s\d+", line).group(0).split(" -> ")[-1][1:])
        trans = line[re.search(r'="', line).span(0)[-1]:re.search(r'"];', line).span(0)[0]]

        # graph[start_state][end_state][0] = trans.split(" / ")[0]
        # graph[start_state][end_state][1] = trans.split(" / ")[-1]

        input_symbol = trans.split(" / ")[0]
        output_symbol = trans.split(" / ")[-1]

        if input_symbol not in graph[start_state]:
            graph[start_state][input_symbol] = [output_symbol, end_state, "blue"]
        else:
            raise Exception("???")
        

    # for i in graph:
    #     print(i)

    return graph
        

def convert_graph_to_dot_lines(graph):
    result = []
    for start_state in range(len(graph)):
        for input_symbol in graph[start_state]:
            result.append(f'\ts{start_state} -> s{graph[start_state][input_symbol][1]} [label="{input_symbol} / {graph[start_state][input_symbol][0]}", color="{graph[start_state][input_symbol][-1]}", fontcolor="{graph[start_state][input_symbol][-1]}"];')

    return result


def main(file_path, draw_pdf=False):
    file_lines = get_file_lines(file_path)
    prefix_list, suffix_list, state_lines = get_prefix_suffix_state_change_lines(file_lines)
    get_dot_graph(state_lines, len(prefix_list) - 2)
    return
    state_lines = merge_state_condition(state_lines)

    total_lines = []
    total_lines.extend(prefix_list)
    total_lines.extend(state_lines)
    total_lines.extend(suffix_list)

    simplify_file_name = f"{os.path.dirname(__file__)}/{file_path[:-4]}_simplify.dot"
    with open(simplify_file_name, "w") as file:
        for line in total_lines:
            file.write(line)
            file.write("\n")

    if draw_pdf:
        os.system(f"dot -Tpdf {simplify_file_name} -o {simplify_file_name[:-4]}.pdf")


def simplify_and_mark(base_dot, state_fuzzing_dot, draw_pdf=True):
    base_file_lines = get_file_lines(base_dot)
    state_fuzzing_lines = get_file_lines(state_fuzzing_dot)

    fuzzing_prefix, fuzzing_suffix, fuzzing_trans_lines = get_prefix_suffix_state_change_lines(state_fuzzing_lines)
    fuzzing_graph = get_dot_graph(fuzzing_trans_lines, len(fuzzing_prefix)-2)
    base_prefix, base_suffix, base_trans_lines = get_prefix_suffix_state_change_lines(base_file_lines)
    base_graph = get_dot_graph(base_trans_lines, len(base_prefix)-2)
    
    base_state_and_fuzzing_state_mapper = {}
    for start_state in range(len(base_graph)):
        print(base_state_and_fuzzing_state_mapper)
        if start_state not in base_state_and_fuzzing_state_mapper and not start_state:
            base_state_and_fuzzing_state_mapper[start_state] = start_state
        fuzzing_start_state = base_state_and_fuzzing_state_mapper[start_state]

        for input_symbol in base_graph[start_state]:
            print(f"base: {start_state} -> {base_graph[start_state][input_symbol][1]} {input_symbol} / {base_graph[start_state][input_symbol][0]}")
            print(f"fuzzing: {fuzzing_start_state} -> {fuzzing_graph[fuzzing_start_state][input_symbol][1]} {input_symbol} / {fuzzing_graph[fuzzing_start_state][input_symbol][0]}")
            if base_graph[start_state][input_symbol][0] == fuzzing_graph[fuzzing_start_state][input_symbol][0]:
                if base_graph[start_state][input_symbol][1] not in base_state_and_fuzzing_state_mapper or (base_state_and_fuzzing_state_mapper[base_graph[start_state][input_symbol][1]] != fuzzing_graph[fuzzing_start_state][input_symbol][1] and fuzzing_graph[fuzzing_start_state][input_symbol][1] < len(base_graph)):
                    base_state_and_fuzzing_state_mapper[base_graph[start_state][input_symbol][1]] = fuzzing_graph[fuzzing_start_state][input_symbol][1]
                if fuzzing_graph[fuzzing_start_state][input_symbol][1] < len(base_graph):
                    fuzzing_graph[fuzzing_start_state][input_symbol][-1] = "black"
                print(base_state_and_fuzzing_state_mapper)

            print("==================")

    fuzzing_trans_lines = convert_graph_to_dot_lines(fuzzing_graph)
    fuzzing_trans_lines = merge_state_condition(fuzzing_trans_lines)
    total_lines = []
    total_lines.extend(fuzzing_prefix)
    total_lines.extend(fuzzing_trans_lines)
    total_lines.extend(fuzzing_suffix)

    simplify_file_name = f"./{state_fuzzing_dot[:-4]}.simplify.dot"
    with open(simplify_file_name, "w") as file:
        for line in total_lines:
            file.write(line)
            file.write("\n")

    if draw_pdf:
        os.system(f"dot -Tpdf {simplify_file_name} -o {simplify_file_name}.pdf")

if __name__ == "__main__":
    # main("./2.dot", False)
    simplify_and_mark("./learnedModel.dot", "./check_learnedModel.dot", True)

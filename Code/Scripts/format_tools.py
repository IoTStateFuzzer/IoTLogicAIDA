import json
import re
import sys
from datetime import datetime, timezone, timedelta

from Config.config_file import abstract_str, threshold_of_random
from Logger import mlog

sys.setrecursionlimit(3000)


"""
tools of http header
"""


def remove_string_by_some_pattern(input_string):
    """
    Use regular expression to match string and modify the substring to abstract string if matching
    :param input_string: string under matching
    :return : string after modified
    """
    def modify_by_pattern(pattern, string_under_modify):
        match = re.search(pattern, string_under_modify)
        if not match:
            return string_under_modify

        while match:
            time_suffix_match = re.search(r"(\.)?\d{3,4}Z?", string_under_modify)
            time_suffix_match = len(re.search(r"(\.)?\d{3,4}Z?", string_under_modify).group()) if time_suffix_match else 0
            replace_str = "|" + "-" * ((len(match.group()) - 3) if time_suffix_match == 6 else (len(match.group()) - 2)) + "|"
            string_under_modify = string_under_modify.replace(match.group(), replace_str)
            match = re.search(pattern, string_under_modify)

        return string_under_modify

    YMD_STR = r"((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))"
    MDY_STR = r"(((((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8])))([-/.]?)([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3}))|(02([-/.]?)29([-/.]?)(([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))))"
    TIME_STR = r"([0-1]?[0-9]|2[0-3])[-:]?([0-5][0-9])[-:]?([0-5][0-9])"
    regex_patterns = [
        r"(?<!\d)[0-9a-zA-Z]{34}(?!\d)",  # gong id
        # r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})",  # ip
        r"((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))((\\s+)|T|_)([0-1]?[0-9]|2[0-3])[-:]?([0-5][0-9])[-:]?([0-5][0-9])(\.)?\d{3,4}Z?",  # \d{4}(-/.)\d{2}(-/.)\d{2}( |T|_)\d{2}:\d{2}:\d{2}.\d{3,4}Z?
        r"((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))((\\s+)|T|_)([0-1]?[0-9]|2[0-3])[-:]?([0-5][0-9])[-:]?([0-5][0-9])Z?",  # \d{4}(-/.)\d{2}(-/.)\d{2}( |T|_)\d{2}:\d{2}:\d{2}Z?
        r"(?<!\d)((([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3})([-/.]?)(((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8]))))|((([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))([-/.]?)02([-/.]?)29))(?!\d)",  # YYYY(-/.)MM(-/.)DD
        r"(?<!\d)(((((0[13578]|1[02])([-/.]?)(0[1-9]|[12][0-9]|3[01]))|((0[469]|11)([-/.]?)(0[1-9]|[12][0-9]|30))|(02([-/.]?)(0[1-9]|[1][0-9]|2[0-8])))([-/.]?)([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3}))|(02([-/.]?)29([-/.]?)(([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00))))(?!\d)",  # MM-/.DD-/.YYYY
        r"(?<!\d)([0-1]?[0-9]|2[0-3])[-:]([0-5][0-9])[-:]([0-5][0-9])(\.)?\d{3,4}Z?(?!\d)",  # HH-:MM-:SS
        r'(?<!\d)(1|2)\d{9,12}(?!\d)',  # timestamp
    ]

    for pattern in regex_patterns:
        input_string = modify_by_pattern(pattern, input_string)

    return input_string


def simply_format_header_feature(header_str: str):
    """
    Use it to keep uri(before "?")
    :param header_str: http uri, such as /a/b/c?d=4
    :return : uri before "?", such as /a/b/c
    """
    # keep the part before the "?"
    # header_str = header_str.split("?")[0]
    return header_str.split("?")[0] if header_str else None


"""
sort tools
"""


def sort_dict_by_key(dictionary):
    sorted_dict = dict(sorted(dictionary.items(), key=lambda x: x[0]))
    return sorted_dict


def sort_dict_by_value(dictionary):
    sorted_dict = dict(sorted(dictionary.items(), key=lambda x: x[1]))
    return sorted_dict


"""
wireshark tools
"""


def transform_timestamp_to_datatime(timestamp, offset=8) -> str:
    """
    transform timestamp to datatime format, such as: 1697782138 ->
    :param timestamp: unix timestamp, such as 1697782138
    :param offset: Offset from UTC, for example: CST=UTC+8
    :return datatime: "YYYY-MM-DD HH:MM:SS.sss"
    """
    timestamp = float(timestamp)
    date_object = datetime.fromtimestamp(timestamp, timezone(timedelta(hours=offset)))
    formatted_time = date_object.strftime("%Y-%m-%d %H:%M:%S")
    return formatted_time


def get_wireshark_filter_by_timestamp(start_timestamp, end_timestamp):
    """
    Generate Wireshark filter expression using timestamp ranges.
    :param start_timestamp: start timestamp
    :param end_timestamp: end timestamp
    :return: wireshark filter expression or None(if the input is wrong)
    """
    # check if end_timestamp is larger than or equal to start_timestamp
    start_timestamp = float(start_timestamp)
    end_timestamp = float(end_timestamp)

    if end_timestamp < start_timestamp:
        mlog.log_func(mlog.ERROR, "Please check your input, end_timestamp should be larger than or equal to start_timestamp")
        mlog.log_func(mlog.ERROR, f"Your input: start_timestamp={start_timestamp}, end_timestamp={end_timestamp}")
        return None
    start_format_time = transform_timestamp_to_datatime(start_timestamp)
    end_format_time = transform_timestamp_to_datatime(end_timestamp)
    wireshark_filter = f'(frame.time >= "{start_format_time}" && frame.time <= "{end_format_time}")'
    return wireshark_filter


def get_wireshark_filter_expression_by_blackname_list_dict(blackname_dict):
    """

    """
    result_condition = []
    if "domain" in blackname_dict:
        for domains in blackname_dict["domain"]:
            if "usere-" in domains:
                continue
            result_condition.append('!(ip.host == "' + domains + '")')
    if "ip" in blackname_dict:
        for ip in blackname_dict["ip"]:
            if "usere-" in ip:
                continue
            result_condition.append('!(ip.addr == ' + ip + ')')

    if result_condition:
        result_condition = " and ".join(result_condition)
        result_condition = "(" + result_condition + ")"
        return result_condition
    return ""


def get_domain_by_ip(ip, domain_mapping_list):
    """
    Mapping ip to domain. First, check if there is a domain name cache in DNS. If not, use socket to obtain the host. If both are unavailable, return the IP.
    :param ip: IP
    :param domain_mapping_list: DNS mapping
    :return: domain or ip
    """
    if isinstance(domain_mapping_list, list):
        for mapping_item in domain_mapping_list:
            if ip in mapping_item:
                return mapping_item[ip]
    elif isinstance(domain_mapping_list, dict):
        if ip in domain_mapping_list:
            if domain_mapping_list[ip] in domain_mapping_list:
                return domain_mapping_list[domain_mapping_list[ip]]
            return domain_mapping_list[ip]
    else:
        mlog.log_func(mlog.ERROR, "dns mapping type error(not list and not dict)")
        exit(-3)
    return ip


def get_wireshark_filter_expression_by_selected_ip_list(ip_list):
    """
    Use ip from ip_list to generate filter expression
    :param ip_list: selected ip
    :return : expression of wireshark
    """
    if not ip_list:
        return None

    # return_expression = "("
    modify_ip_list = []
    for index in range(len(ip_list)):
        if not ip_list[index]:
            continue
        modify_ip_list.append(f"ip.addr == {ip_list[index]}")
    return_expression = f"({' or '.join(modify_ip_list)})"

    return return_expression


def get_merged_wireshark_filter_expression(expression_list):
    not_none_expression_list = []
    for exp in expression_list:
        if exp and isinstance(exp, str):
            not_none_expression_list.append(exp)
    return " and ".join(not_none_expression_list)


"""
Template extraction based on randomness assessment
"""


def merge_pattern(pattern_list: list):
    pattern_item_list = pattern_list.copy()

    # merge
    merged_pattern = []
    while pattern_item_list:
        cur_item = pattern_item_list.pop(0)
        if abstract_str not in cur_item:
            merged_pattern.append(cur_item)
        else:
            new_len = int(cur_item[len(abstract_str):-1])
            while pattern_item_list and abstract_str in pattern_item_list[0]:
                new_len += int(pattern_item_list.pop(0)[len(abstract_str):-1])
            merged_pattern.append(f"{abstract_str}{new_len}|")

    return merged_pattern


def get_suffix_by_prefix(cur_prefix, separator_list, value_list, pattern_list, threshold):
    def get_value_fp_list(cur_prefix, value_list):
        # get next value_fp_list for current prefix
        if int(len(cur_prefix) / 2) < len(value_list):
            return value_list[int(len(cur_prefix) / 2)]
        else:
            return []

    def get_value_pattern(value_fp_list):
        # if len(value_fp_list) > 1 and len(set(value_fp_list)) / len(value_fp_list) > threshold:
        if len(value_fp_list) > 2 and (len(set(value_fp_list)) / len(value_fp_list) > threshold or len(set(value_fp_list)) > 5):
            return [abstract_str + str(len(value_fp_list[0])) + "|"]
        else:
            return deduplicate_for_list(value_fp_list)

    def get_next_separator(cur_prefix, separator_list):
        if separator_list[0] == cur_prefix[0]:
            if int((len(cur_prefix) + 1) / 2) < len(separator_list):
                return separator_list[int((len(cur_prefix) + 1) / 2)]
            else:
                return ""
        else:
            if int(len(cur_prefix) / 2) < len(separator_list):
                return separator_list[int(len(cur_prefix) / 2)]
            else:
                return ""

    # main
    value_fp_lit = get_value_fp_list(cur_prefix, value_list)

    if value_fp_lit:
        value_pattern_list = get_value_pattern(value_fp_lit)
        for value_pattern in value_pattern_list:
            next_prefix = cur_prefix.copy()
            next_prefix.append(value_pattern)
            next_prefix.append(get_next_separator(next_prefix, separator_list))

            # get value_list for current pattern
            if len(value_pattern_list) == 1:
                get_suffix_by_prefix(next_prefix, separator_list, value_list, pattern_list, threshold)
            else:
                next_value_index_list = []
                for index in range(len(value_fp_lit)):
                    if value_fp_lit[index] == value_pattern:
                        next_value_index_list.append(index)
                next_value_list = []
                for i in range(len(value_list)):
                    temp_value_col = []
                    for index in next_value_index_list:
                        temp_value_col.append(value_list[i][index])
                    next_value_list.append(temp_value_col.copy())
                get_suffix_by_prefix(next_prefix, separator_list, next_value_list.copy(), pattern_list, threshold)
    else:
        if cur_prefix:
            pattern_list.append(cur_prefix)
        return


def get_patterns_for_cases(cases, readable_flag=True, threshold=threshold_of_random):
    def get_readable_patterns_for_cases(cases):
        def get_separators_and_values(same_len_input_list):
            # transform to string
            str_input_list = [str(x) for x in same_len_input_list]

            # check len
            check_len = len(str_input_list[0])
            for x in str_input_list:
                if len(x) != check_len:
                    mlog.log_func(mlog.ERROR,
                                  "Please check your input: ensure that all content in the input is of the same length")
                    mlog.log_list_func(mlog.ERROR, str_input_list)
                    exit(111)

            # get separator list and value index information
            value_fp_index_list = []
            separator_list = []
            pattern_result = ""
            cur_value_fp = []
            for str_index in range(len(str_input_list[0])):
                cur_chr = str_input_list[0][str_index]
                break_flag = False
                for string in str_input_list[1:]:
                    if string[str_index] != cur_chr:
                        if str_index == 0 or pattern_result != "":
                            separator_list.append(pattern_result)
                            pattern_result = ""
                        break_flag = True
                        if len(cur_value_fp) == 0:
                            cur_value_fp.append(str_index)
                        break
                if not break_flag:
                    pattern_result += cur_chr
                    if len(cur_value_fp) == 1:
                        cur_value_fp.append(str_index)
                        value_fp_index_list.append(cur_value_fp.copy())
                        cur_value_fp.clear()

            # check if cur_value_fp has only one position
            if len(cur_value_fp) == 1:
                value_fp_index_list.append(cur_value_fp.copy())
            if pattern_result != "":
                separator_list.append(pattern_result)

            # get value list
            value_list = []
            for string_index_list in value_fp_index_list:
                temp_list = []
                for string in str_input_list:
                    if len(string_index_list) == 2 and string_index_list[0] < string_index_list[1]:
                        temp_list.append(string[string_index_list[0]:string_index_list[1]])
                    else:
                        temp_list.append(string[string_index_list[0]:])
                value_list.append(temp_list.copy())

            return separator_list, value_list

        cases = deduplicate_for_list(cases)
        for index in range(len(cases)):
            cases[index] = cases[index].replace(abstract_str, "Bbs_Len")

        # extract patterns
        separator_list, value_list = get_separators_and_values(cases)
        init_prefix = [separator_list[0]]
        patterns = []
        get_suffix_by_prefix(init_prefix, separator_list, value_list, patterns, threshold=threshold)
        # replace and merge
        for each_pattern_index in range(len(patterns)):
            patterns[each_pattern_index] = merge_abs_len_str_for_pattern_str(
                "".join(patterns[each_pattern_index]).replace("Bbs_Len", abstract_str))
        patterns = deduplicate_for_list(patterns)
        for each_pattern_index in range(len(patterns)):
            patterns[each_pattern_index] = split_feature_str_to_pattern_list(patterns[each_pattern_index])

        return patterns

    def get_unreadable_payload_pattern(cases):
        # check readable
        check_flag = True
        for case in cases:
            case_split = case.split(":")
            for item in case_split:
                if len(item) != 2:
                    check_flag = False
                    break

        if check_flag:
            # get readable char list
            is_readable_char_list = [1] * len(cases[0].split(":"))

            for index in range(len(is_readable_char_list)):
                for item in cases:
                    if not ("7E" >= item.split(":")[index] >= "20"):
                        is_readable_char_list[index] = 0
                        break

            zero_count = 0
            one_count = 0
            udp_payload_pattern_by_readable_list = []
            for index in range(len(is_readable_char_list)):
                if is_readable_char_list[index]:
                    if zero_count:
                        udp_payload_pattern_by_readable_list.append(abstract_str + str(zero_count) + "|")
                        zero_count = 0
                    one_count += 1
                else:
                    if one_count:
                        udp_payload_pattern_by_readable_list.append(one_count)
                        one_count = 0
                    zero_count += 1
            if zero_count:
                udp_payload_pattern_by_readable_list.append(abstract_str + str(zero_count) + "|")
            if one_count:
                udp_payload_pattern_by_readable_list.append(one_count)

            # convert byte to text
            for case_index in range(len(cases)):
                case_split = cases[case_index].split(":")
                temp_case = []
                readable_item_index = 0
                case_split_index = 0
                while readable_item_index < len(udp_payload_pattern_by_readable_list):
                    if type(udp_payload_pattern_by_readable_list[readable_item_index]) == int:
                        temp_str = ""
                        for count_index in range(udp_payload_pattern_by_readable_list[readable_item_index]):
                            temp_str += chr(int(case_split[case_split_index + count_index], 16))
                        case_split_index = case_split_index + udp_payload_pattern_by_readable_list[readable_item_index]
                        temp_case.append(temp_str)
                    else:
                        t_count = int(udp_payload_pattern_by_readable_list[readable_item_index][7:-1])
                        # case_split_index += (t_count + 1)
                        case_split_index += t_count
                        temp_case.append(udp_payload_pattern_by_readable_list[readable_item_index])

                    readable_item_index += 1

                cases[case_index] = "".join(temp_case)

        temp_patterns = get_readable_patterns_for_cases(cases)

        for pattern_index in range(len(temp_patterns)):
            temp_after_process_pattern = []
            for pat_item in temp_patterns[pattern_index]:
                if pat_item:
                    temp_after_process_pattern.extend(split_feature_str_to_pattern_list(pat_item))

            # merge
            temp_patterns[pattern_index] = merge_pattern(temp_after_process_pattern)

        return temp_patterns

    def convert_pattern_to_str(pattern):
        converted_str = ""
        for item in pattern:
            if abstract_str in item:
                item = "1" * int(item.replace(abstract_str, "")[:-1])
            converted_str += item
        return converted_str

    return_patterns = get_readable_patterns_for_cases(cases) if readable_flag else get_unreadable_payload_pattern(cases)

    # remove pattern which can be matched by other
    while True:
        matched_flag = False
        for i in range(len(return_patterns)):
            if i >= len(return_patterns):
                break
            current_pattern = return_patterns.pop(i)
            for j in range(len(return_patterns) - 1, -1, -1):
                if pattern_matching(convert_pattern_to_str(return_patterns[j]), [current_pattern]):
                    matched_flag = True
                    return_patterns.pop(j)
            return_patterns.insert(0, current_pattern)
        if not matched_flag:
            break

    return return_patterns



def merge_abs_len_str_for_pattern_str(pattern_str: str):
    pattern_item_list = split_feature_str_to_pattern_list(pattern_str)

    # merge
    merged_pattern = []
    while pattern_item_list:
        cur_item = pattern_item_list.pop(0)
        if abstract_str not in cur_item:
            merged_pattern.append(cur_item)
        else:
            new_len = int(cur_item[len(abstract_str):-1])
            while pattern_item_list and abstract_str in pattern_item_list[0]:
                new_len += int(pattern_item_list.pop(0)[len(abstract_str):-1])
            merged_pattern.append(f"{abstract_str}{new_len}|")

    return "".join(merged_pattern)


"""
    Use pattern to match
"""


def get_regular_expression_from_pattern(pattern_split: list):
    """

    :param pattern_split: Split pattern list, such as
                ["{\"header\":{\"notifyType\":\"deviceDeleted\",\"category\":\"device\",\"timestamp\":\"|--------------|\"},\"body\":{\"devId\":\"",
                "Abs_Len8|",
                "-",
                "Abs_Len4|",
                "-4"]
    :return : regular expression
    """
    regular_expression = ""
    abs_re = abstract_str + r"\d{1,}\|"
    for unit in pattern_split:
        if abstract_str not in unit or len(re.findall(abs_re, unit)) > 1:
            regular_expression += re.escape(unit)
        else:
            if "|" in unit:
                unit = unit.replace("|", "")
            abs_len = unit.split(abstract_str)[-1]
            regular_expression += ".{" + abs_len + "}"  # get regular expression
    return regular_expression


def pattern_matching(case, patterns, is_hex=False):
    """
    Use patterns to match case. If matching, return pattern. If not, return None
    :param case: case under matching
    :param patterns: patterns
    :param is_hex: If case is hex data, check whether hex string is printable charactor
    :return : If matching, return pattern, else, return None
    """
    # if is_raw_data(case):
    if is_hex:
        raw_case = case
        try:
            case_split = case.split(":")
            case_str = ""
            for index in range(len(case_split)):
                case_str += chr(int(case_split[index], 16)) if "7E" >= case_split[index] >= "20" else "8"
            case = case_str
        except ValueError:
            mlog.log_func(mlog.ERROR, f"ValueError in format_tools.py--pattern_matching(), current case: {raw_case}\n\tcurrent patterns: {patterns}")
            exit(-2)

    case = case.replace(abstract_str, "Bbs_Len")

    for pattern in patterns:
        if isinstance(pattern, list):
            pattern_str = get_regular_expression_from_pattern(pattern)
            if pattern_str == "payload_is_None" and (not case or case == pattern_str):
                return pattern
            if re.match(pattern_str, case):
                return pattern
        elif isinstance(pattern, str):
            if "usere-" not in pattern[:6] and pattern == case.replace("Bbs_Len", abstract_str):
                return pattern
            elif "usere-" in pattern[:6] and re.match(f"{pattern.replace('usere-', '')}$", case):
                return pattern.replace('usere-', '')

    # case = case.replace("Bbs_Len", abstract_str)
    return None

    # select pattern has a minimum of str_None_abslen
    """
    [todo]
    """


def get_pattern_index_in_pattern_list(pattern, pattern_list):
    try:
        current_pattern_str = "".join(pattern)
        for pattern_index in range(len(pattern_list)):
            if current_pattern_str == "".join(pattern_list[pattern_index]):
                return pattern_index
        return -1
    except TypeError:
        mlog.log_func(mlog.ERROR, f"TypeError, bad pattern: {pattern}")
        return -1


def split_feature_str_to_pattern_list(feature_str, abs_re=abstract_str+r"\d{1,}\|"):
    """

    :param feature_str:
    :return : pattern list of feature_str
    """
    match = re.search(abs_re, feature_str)
    temp_list = []
    while match:
        if match.span()[0] > 0:
            temp_list.append(feature_str[:match.span()[0]])
        temp_list.append(feature_str[match.span()[0]: match.span()[1]])

        # update
        feature_str = feature_str[match.span()[1]:]
        match = re.search(abs_re, feature_str)
    if feature_str:
        temp_list.append(feature_str)

    return temp_list


def get_feature_pattern_str(header_feature_str, patterns):
    match_pattern = pattern_matching(header_feature_str, patterns)
    return "".join(patterns[get_pattern_index_in_pattern_list(match_pattern, patterns)])


"""
    format strings
"""


def remove_blank_from_list(list_under_progress: list):
    for i in range(len(list_under_progress)-1, -1, -1):
        if not list_under_progress[i]:
            list_under_progress.pop(i)
    return list_under_progress


def is_raw_data(cur_feature, threshold=0.9):
    # printable = sum(c in bytes(range(32, 127)) or c in b'\n\r\t' for c in cur_feature)
    # return not (printable / len(cur_feature)) > threshold if len(cur_feature) > 0 else False
    raw_data_protocols = ["udp", "tcp", "mqtt", "pppp"]
    for protocol in raw_data_protocols:
        if protocol in cur_feature.split("|")[2]:
            return True
    return False


def hex_to_ascii(hex_string):
    hex_parts = hex_string.split(':')

    ascii_string = ''.join(chr(int(hex_part, 16)) for hex_part in hex_parts)

    return ascii_string


def convert_seconds_to_time(seconds):
    seconds = int(seconds)
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return "{:02d}:{:02d}:{:02d}".format(int(hours), int(minutes), int(seconds))


def deduplicate_for_list(raw_list):
    return list(set(raw_list))

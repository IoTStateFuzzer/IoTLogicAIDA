import json
import os
import csv

from Scripts import format_tools


def main(database_list, step_list):
    protocol_to_be_filtered = ["http", "udp", "tcp"]
    with open("../../../Mapper/Monitor/black_list.json", "r") as bf:
        black_dict = json.load(bf)

    def step1(dataset_path):
        all_packet_folder_list = os.listdir(dataset_path)

        for threshold_among_each_kind_of_action in range(10, 101, 10):
            threshold_among_each_kind_of_action = threshold_among_each_kind_of_action/100

            # Collect statistics on features whose number of occurrences exceeds the threshold
            feature_filter_by_general_list = []
            # add from black list
            if "full_feature" in black_dict:
                feature_filter_by_general_list.extend(black_dict["full_feature"])

            feature_ops_dict = {}
            count_of_op = 0

            # get feature aggregation from each csv and static appearance time
            for distance_folder in all_packet_folder_list:
                if not os.path.isdir(dataset_path + distance_folder):
                    continue

                distance_folder_path = dataset_path + distance_folder + "/"
                under_distance_files = os.listdir(distance_folder_path)

                for user_pcap_txt in under_distance_files:
                    if not os.path.isdir(distance_folder_path + user_pcap_txt):
                        continue
                    user_folder_path = distance_folder_path + user_pcap_txt + "/"
                    action_folders = os.listdir(user_folder_path)

                    for action in action_folders:
                        if not os.path.isdir(user_folder_path + action):
                            continue

                        abs_action_folder = user_folder_path + action + "/"

                        full_action_name = f"{distance_folder}|{user_pcap_txt}|{action}"
                        count_of_op += 1
                        file_list = os.listdir(abs_action_folder)

                        for cur_file in file_list:
                            # find csv file
                            if cur_file[-3:] != "csv":
                                continue

                            # read csv file
                            with open(abs_action_folder + cur_file, "r") as file:
                                reader = csv.reader(file)
                                header = next(reader)
                                for line in list(reader):
                                    cur_line_feature = "|".join(line[header.index("domain"):])

                                    # filter by black list
                                    is_black = False
                                    for black_key in black_dict.keys():
                                        if black_key == "ip" and (format_tools.pattern_matching(line[header.index("src")],
                                                                                                black_dict[black_key])
                                                                  or format_tools.pattern_matching(
                                                    line[header.index("dst")], black_dict[black_key])):
                                            is_black = True
                                        elif black_key == "full_feature" and format_tools.pattern_matching(cur_line_feature,
                                                                                                           black_dict[
                                                                                                               black_key]):
                                            is_black = True
                                        elif black_key in header and format_tools.pattern_matching(
                                                line[header.index(black_key)], black_dict[black_key]):
                                            is_black = True
                                        if is_black:
                                            feature_filter_by_general_list.append(cur_line_feature)
                                            break

                                    # check if current protocol should be filtered
                                    if is_black or (line[header.index("protocol")] not in protocol_to_be_filtered) or (
                                            cur_line_feature in feature_filter_by_general_list):
                                        continue

                                    if cur_line_feature not in feature_ops_dict:
                                        feature_ops_dict[cur_line_feature] = [full_action_name]
                                    elif full_action_name not in feature_ops_dict[cur_line_feature]:
                                        feature_ops_dict[cur_line_feature].append(full_action_name)

            # static
            feature_ops_dict = format_tools.sort_dict_by_key(feature_ops_dict)
            for feature in feature_ops_dict:
                with open(f"../../../Mapper/Monitor/white_list.json", "r") as white_file:
                    white_dict = json.load(white_file)

                is_white = False
                # for field in white_dict.keys():
                #     if is_white:
                #         break
                #     for white_item in white_dict[field]:
                #         if white_item.replace("mustsel-", "") in feature:
                #             is_white = True
                #             break

                if not is_white and len(feature_ops_dict[feature]) > threshold_among_each_kind_of_action * count_of_op:
                    feature_filter_by_general_list.append(feature)

            feature_filter_by_general_list = format_tools.deduplicate_for_list(feature_filter_by_general_list)
            feature_filter_by_general_list.sort()

            print(dataset_path.split('/')[-2], int(threshold_among_each_kind_of_action*100))
            # record feature in black list
            if not os.path.exists(f"Step3/{dataset_path.split('/')[-2]}/"):
                os.mkdir(f"Step3/{dataset_path.split('/')[-2]}/")
            with open(
                    f"Step3/{dataset_path.split('/')[-2]}/{int(threshold_among_each_kind_of_action * 100)}_filtered_features.txt", "w") as f:
                for feature in feature_filter_by_general_list:
                    f.write(feature)
                    f.write("\n")

    def step2(dataset_path, step1_threshold=50):
        all_packet_folder_list = os.listdir(dataset_path)
        with open(f"Step3/{dataset_path.split('/')[-2]}/{step1_threshold}_filtered_features.txt", "r") as f:
            feature_filter_by_general_list = [x.replace("\n", "") for x in f.readlines()]
            # print(feature_filter_by_general_list)

        with open(f"../../../Mapper/Monitor/white_list.json", "r") as white_file:
            white_dict = json.load(white_file)

        for threshold_in_one_op in range(10, 101, 10):
            threshold_in_one_op = threshold_in_one_op / 100
            # threshold_in_one_op = 0.8

            # construct: {action: {click_item: {feature: [payload_list]}}}
            features_occur_for_each_time_dict = {}  # It is used to count the pattern corresponding to each feature when each click is executed under each action

            # get feature aggregation from each csv and static appearance time
            for distance_folder in all_packet_folder_list:
                if not os.path.isdir(dataset_path + distance_folder):
                    continue
                if distance_folder not in features_occur_for_each_time_dict.keys():
                    features_occur_for_each_time_dict[distance_folder] = {}
                distance_folder_path = dataset_path + distance_folder + "/"
                under_distance_files = os.listdir(distance_folder_path)

                for user_pcap_txt in under_distance_files:
                    if not os.path.isdir(distance_folder_path + user_pcap_txt):
                        continue
                    if user_pcap_txt not in features_occur_for_each_time_dict[distance_folder]:
                        features_occur_for_each_time_dict[distance_folder][user_pcap_txt] = {}
                    user_folder_path = distance_folder_path + user_pcap_txt + "/"
                    action_folders = os.listdir(user_folder_path)

                    for action in action_folders:
                        action_folder = user_folder_path + action + "/"
                        if not os.path.isdir(action_folder):
                            continue

                        fea_times_in_cur_op_dict = {}

                        if action not in features_occur_for_each_time_dict[distance_folder][user_pcap_txt]:
                            features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action] = dict()

                        # for item in os.listdir(action_folder):
                        for item in [x for x in os.listdir(action_folder) if x.split(".")[-1] == "csv"]:
                            cur_action_item = "_".join(item.split("_")[:-1]).split("|")[-1]
                            # add action_timestamp to dict
                            if cur_action_item not in features_occur_for_each_time_dict[distance_folder][user_pcap_txt][
                                action]:
                                features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][
                                    cur_action_item] = {}

                            # read csv file and get appear time for each feature
                            with open(action_folder + item, "r") as file:
                                reader = csv.reader(file)
                                header = next(reader)
                                for line in list(reader):
                                    cur_line_feature = "|".join(line[header.index("domain"):])

                                    # check if current line feature is filtered
                                    if cur_line_feature in feature_filter_by_general_list:  # or line[protocol_index] not in protocol_to_be_filtered:
                                        continue

                                    # Add feature to the dictionary which will be used later to add payload
                                    if cur_line_feature not in \
                                            features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][
                                                cur_action_item]:
                                        features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][
                                            cur_action_item][cur_line_feature] = []

                                    # Add to the dictionary of counts
                                    if cur_line_feature not in fea_times_in_cur_op_dict:
                                        fea_times_in_cur_op_dict[cur_line_feature] = []
                                    if f'{user_pcap_txt}|{distance_folder}|{cur_action_item}' not in \
                                            fea_times_in_cur_op_dict[cur_line_feature]:
                                        fea_times_in_cur_op_dict[cur_line_feature].append(
                                            f'{user_pcap_txt}|{distance_folder}|{cur_action_item}')

                        if not os.path.exists(f"./Step3/{dataset_path.split('/')[-2]}/"):
                            os.mkdir(f"./Step3/{dataset_path.split('/')[-2]}/")

                        selected_file_handle = open(f"./Step3/{dataset_path.split('/')[-2]}/step1_{step1_threshold}_step2_{int(threshold_in_one_op * 100)}_{distance_folder}|{user_pcap_txt}|{action}_select.txt", "w")
                        cur_action_threshold = threshold_in_one_op * len([x for x in os.listdir(action_folder) if x.split(".")[-1] == "txt" and action in x])
                        for feature in fea_times_in_cur_op_dict:
                            jump_flag = True
                            for protocol in protocol_to_be_filtered:
                                if f"|{protocol}|" in feature:
                                    jump_flag = False
                            if jump_flag:
                                continue

                            is_white = False
                            for field in white_dict.keys():
                                if is_white:
                                    break
                                for white_item in white_dict[field]:
                                    if "mustsel-" not in white_item:
                                        continue
                                    if white_item[len("mustsel-"):] in feature:
                                        is_white = True
                                        break
                            if not is_white and len(fea_times_in_cur_op_dict[feature]) < cur_action_threshold:
                                pass
                            else:
                                selected_file_handle.write(f"{feature}\n")
                        selected_file_handle.close()

    for test_database in database_list:
        test_database = f"../../../Mapper/Monitor/packets/z_databases/{test_database}/"

        if 1 in step_list:
            step1(test_database)
        if 2 in step_list:
            step2(test_database, step1_threshold=60)


def get_all_select_feature(database_list):
    for test_database in database_list:
        save_path = f"Step3/{test_database}/0selected_features.txt"
        test_database = f"../../../Mapper/Monitor/packets/z_databases/{test_database}/"

        sel_features = []

        for distance in ["local", "remote"]:
            for user in ["user1", "user2"]:
                user_folder = f"{test_database}/{distance}/{user}"
                if not os.path.exists(user_folder):
                    continue
                for action in os.listdir(user_folder):
                    sel_features.append(f"{distance}|{user}|{action}\n")
                    with open(f"{user_folder}/{action}/0selected_features.txt") as f:
                        sel_features.extend(f.readlines())
                    sel_features.append("\n\n")

        with open(save_path, "w") as f:
            f.writelines(sel_features)


def check_step1_fp(database_list):
    for test_database in database_list:
        sel_feature_path = f"./Step2/{test_database}/0selected_features.txt"
        print(test_database)
        print("===============================================")

        with open(sel_feature_path, "r") as fea_f:
            # sel_features = [x.replace('\n', '') for x in fea_f.readlines() if len(x.split('|')) > 3]
            sel_features = [x.replace("\n", "") for x in fea_f.readlines() if len(x.split('|')) > 3]
            sel_features = list(set(sel_features))

        for filtered_file in sorted(os.listdir(f"Step2/{test_database}")):
            if "filtered_features.txt" not in filtered_file:
                continue

            with open(f"Step3/{test_database}/{filtered_file}", "r") as general_filtered_feature_handle:
                fil_features = [x.replace("\n", "") for x in general_filtered_feature_handle.readlines() if "usere-" not in x and "|mqtt|" not in x and "|pppp|" not in x]

            FP_count = 0
            FP_list = []
            for feature in sel_features:
                if feature in fil_features:
                    FP_list.append(feature)
                    FP_count += 1

            print(filtered_file)
            print("Total filtered features(-1): ", len(fil_features)-1)
            print("TP: ", len(fil_features)-1-FP_count)
            print("FP: ", FP_count)
            print(FP_list)
            print("----------------")


def check_step2_existence(database_list):
    with open(f"./all_feature_number.txt", "r") as f:
        all_feature_count_dict = {}
        cur_database = None
        for line in f.readlines():
            if "_database_" in line:
                cur_database = line.replace("\n", "")
                all_feature_count_dict[cur_database] = 0
            elif "static_count:" in line:
                all_feature_count_dict[cur_database] = int(line.split()[-1])

    for test_database in database_list:
        # if "huawei" not in test_database:
        #     continue
        sel_feature_path = f"./Step2/{test_database}/0selected_features.txt"
        print(test_database)
        print("===============================================")

        with open(sel_feature_path, "r") as fea_f:
            lines = fea_f.readlines()
            action_list = [x.replace("\n", "") for x in lines if len(x.split('|')) == 3]
            action_feature_dict = {}
            cur_action = None
            for line in lines:
                line = line.replace("\n", "")
                if not line:
                    continue
                if line in action_list:
                    action_feature_dict[line] = []
                    cur_action = line
                else:
                    action_feature_dict[cur_action].append(line)

        total_select_by_threshold = {}
        FN_count_by_threshold = {}
        for cur_action in action_feature_dict.keys():
            act_files = [x for x in os.listdir(f"./Step3/{test_database}") if cur_action in x and ".txt" in x]
            threshold_result = {}
            for act_file in act_files:
                step2_threshold = act_file.split("_")[3]
                # if step2_threshold != "90":
                #     continue
                threshold_result[step2_threshold] = []
                if step2_threshold not in total_select_by_threshold:
                    total_select_by_threshold[step2_threshold] = []
                if step2_threshold not in FN_count_by_threshold:
                    FN_count_by_threshold[step2_threshold] = 0

                with open(f"./Step3/{test_database}/{act_file}", "r") as act_file_handle:
                    threshold_select_features = [x.replace("\n", "") for x in act_file_handle.readlines()]
                    total_select_by_threshold[step2_threshold].extend(threshold_select_features)

                threshold_result[step2_threshold].append(action_feature_dict[cur_action])
                threshold_result[step2_threshold].append(threshold_select_features)
                is_include = set(action_feature_dict[cur_action]) & set(threshold_select_features) == set(action_feature_dict[cur_action])
                threshold_result[step2_threshold].append(is_include)
                if not is_include:
                    FN_count_by_threshold[step2_threshold] += 1
                    print(cur_action, step2_threshold)
                    FN_set = set(action_feature_dict[cur_action]) - set(threshold_select_features)
                    print(len(FN_set), FN_set)
                    threshold_result[step2_threshold].append(list(FN_set))
                    threshold_result[step2_threshold].append(len(FN_set))

                threshold_result[step2_threshold].append(f"{len(threshold_select_features)}/{all_feature_count_dict[test_database]}")

            threshold_result = dict(sorted(threshold_result.items(), key=lambda x: x[0]))
            with open(f"./Step3/{test_database}/0{cur_action}_result.json", "w") as result_file_handle:
                json.dump(threshold_result, result_file_handle, indent=4)
        print("------------")

        total_select_by_threshold = format_tools.sort_dict_by_key(total_select_by_threshold)
        for threshold in total_select_by_threshold:
            print("*******")
            print(threshold)
            total_select_by_threshold[threshold] = format_tools.deduplicate_for_list(total_select_by_threshold[threshold])
            print(f"({all_feature_count_dict[test_database]}-{len(total_select_by_threshold[threshold])})={all_feature_count_dict[test_database]-len(total_select_by_threshold[threshold])}/{all_feature_count_dict[test_database]}={(all_feature_count_dict[test_database]-len(total_select_by_threshold[threshold]))/all_feature_count_dict[test_database]}")
            print(f"FN action rate: {FN_count_by_threshold[threshold]/len(action_feature_dict.keys())}")

        print()
        print()


def count_all_features(database_list):
    for test_database in database_list:
        print(test_database)
        test_database = f"../../../Mapper/Monitor/packets/z_databases/{test_database}/"
        all_filtered_feature_list = []

        with open(f"{test_database}/0feature_static.json", "r") as f:
            outside_feature_static = set(json.load(f).keys())

        with open(f"{test_database}/0filtered_features.txt", "r") as f:
            all_filtered_feature_list.extend([x.replace("\n", "") for x in f.readlines() if "usere-" not in x and "|mqtt|" not in x and "|pppp|" not in x])

        for distance in ["local", "remote"]:
            for user in ["user1", "user2"]:
                user_folder = f"{test_database}/{distance}/{user}"
                if not os.path.exists(user_folder):
                    continue
                for action in os.listdir(user_folder):
                    with open(f"{user_folder}/{action}/0feature_static.json", "r") as f:
                        all_filtered_feature_list.extend([x for x in json.load(f).keys() if "|mqtt|" not in x and "|pppp|" not in x])
        all_filtered_feature_list = set(all_filtered_feature_list)

        print("outside_feature_static: ", len(outside_feature_static))
        print("static_count: ", len(all_filtered_feature_list))
        print(all_filtered_feature_list - set(outside_feature_static))
        print("===============================")


if __name__ == "__main__":
    database_list = os.listdir("../../../Mapper/Monitor/packets/z_databases/")
    # main(database_list, step_list=[1])
    # check_step1_fp(database_list)
    check_step2_existence(database_list)
    # count_all_features(database_list)

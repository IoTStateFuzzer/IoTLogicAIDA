import json
import os
import warnings
from Logger import mlog


class InputSequence(object):
    def __init__(self, ui_scan_folder: str, sequence: list=[]):
        self._sequence = sequence
        self._removed_seq = []
        self._has_action_in_current_round = bool(self._sequence)

        ui_scan_file = f"{ui_scan_folder}/button_constrain.json" if "/" in ui_scan_folder else f"{os.path.dirname(__file__)}/../../Alphabet/ui_scan_result/{ui_scan_folder}/button_constrain.json"
        if not os.path.exists(ui_scan_file):
            self.constrain_dict = dict()
            self.conflict_dict = dict()
        else:
            with open(ui_scan_file, "r") as con_file:
                constrain_config = json.load(con_file)
            self.conflict_dict = constrain_config["conflict_dict"]
            self.constrain_dict = constrain_config["constrain_dict"]

    def add(self, inpt: str):
        try:
            _input = inpt
            return_flag = self.check_clickable(_input)
            if return_flag:
                if _input in self.conflict_dict:
                    self._delete_conflict_items(_input)
                self._sequence.append(_input)
            self._has_action_in_current_round = True
            return return_flag
        except Exception as e:
            mlog.log_func(mlog.ERROR, "-----UNKNOWN ERROR WHEN ADD TO CACHE-----\n")
            mlog.log_func(mlog.ERROR, e)
            exit(-2)

    def check_clickable(self, inpt: str):
        _input = inpt
        # global constrain_dict, conflict_dict
        if _input in self.constrain_dict:
            # get constrains of current input
            _constrains = self.constrain_dict[_input]
            if isinstance(_constrains, list):
                has_or_action = False
                for _cons in _constrains:
                    if "or|" == _cons[:3]:
                        has_or_action = True
                        if _cons[3:] in self._sequence:
                            return True
                        else:
                            continue
                    elif "not|" == _cons[:4] and _cons[4:] not in self._sequence:
                        continue
                    elif _cons in self._sequence:
                        continue
                    return False
                return True if not has_or_action else False
            elif isinstance(_constrains, str):
                if "not|" == _constrains[:4] and _constrains[4:] not in self._sequence:
                    return True
                if _constrains in self._sequence:
                    return True
            else:
                warnings.warn("ERROR 02 OCCUR: UNKNOWN CONSTRAIN TYPE!\n")
            return False
        return True

    def _delete_conflict_items(self, inpt):
        _input = inpt
        # get conflict items from conflict_dict
        _conflict_items = self.conflict_dict[_input]
        pop_item = None
        if isinstance(_conflict_items, str):
            # just one conflict item
            for item_index in range(len(self._sequence) - 1, -1, -1):
                if self._sequence[item_index] == _conflict_items:
                    pop_item = self._sequence.pop(item_index)
        elif isinstance(_conflict_items, list):
            for item_index in range(len(self._sequence) - 1, -1, -1):
                if self._sequence[item_index] in _conflict_items:
                    pop_item = self._sequence.pop(item_index)
        self._removed_seq.append(pop_item)

    def clean(self):
        try:
            self._sequence = []
            self._removed_seq = []
            self._has_action_in_current_round = False
            mlog.log_func(mlog.LOG, "Clean cache success")
        except Exception as e:
            mlog.log_func(mlog.ERROR, "Clean cache error")
            mlog.log_func(mlog.ERROR, e)

    def show(self):
        mlog.log_func(mlog.LOG, f"Current run cache: {self._sequence}")

    def get_run_cache(self):
        return self._sequence

    def has(self, operation):
        return operation in self._sequence

    def is_empty(self):
        return not bool(len(self._sequence))

    def get_removed_seq(self):
        return self._removed_seq

    def has_executed_action_in_current_round(self):
        return self._has_action_in_current_round

    def actionA_later_than_actionB(self, actionA, actionB):
        if self.has(actionA) and not self.has(actionB):
            return True
        elif not self.has(actionA):
            return False
        else:
            index_a = -1
            index_b = -1
            for i in range(len(self._sequence)-1, -1, -1):
                if self._sequence[i] == actionA:
                    index_a = i
                    break
            for i in range(len(self._sequence)-1, -1, -1):
                if self._sequence[i] == actionB:
                    index_b = i
                    break
            return index_a > index_b

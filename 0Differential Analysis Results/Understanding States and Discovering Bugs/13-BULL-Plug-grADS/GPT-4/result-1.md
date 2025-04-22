Initial state machine exploration has given the following semantics where we reason about the semantics of a state by considering the sequence of actions that led to it. The semantics of each state for the two machines are:
* s0: Initial state ¨C no device added (both base and fuzzing model).
* s1: Device added by User1 (both base and fuzzing model). Only user1 has control of the device.
* s2: Inaccessible state (in both base and fuzzing model).
* s3: User1 shares device (in both base and fuzzing model). User2 prompts the device share but does not yet accept. 
* s4: User2 accepts device share in basemodel and in statefuzzing (in basemodel, user2 legally controls the device. in statefuzzing, user2 has the ability to replay the AcceptDeviceShare action)
* s5: This state only exists in the statefuzzing model. In this state, user1 has revoked user2's legal control of the device, but user2 still has the replay ability of AcceptDeviceShare.
* s6: A state only in statefuzzing model, signifying the device has been removed by user1 (but user2 still holds the replay ability of AcceptDeviceShare)
* s7: A state only in statefuzzing model, a situation where user1 shares the device again after UnsharePlug in state s5.

From this analysis, a potential vulnerability scenario may exist from s3 to s4 in statefuzzing. Even after user1 revokes the control of user2 from the device, user2 still retains the capability to replay the AcceptDeviceShare action. If user2 is an attacker, it might exploit this capability to regain control of the device.

There are no visible vulnerabilities detected in basemodel, but focusing on the statefuzzing model, given the statefuzzing model keeps track of user2¡¯s ability to replay the AcceptDeviceShare action even after it was unshared, state transitions happening in the smart-home could be exploited if an attacker gets hold of user2 privileges, just like it is represented in the statefuzzing model from states s4 to s7.

The vulnerability presents the idea of excessive privileges to an attacker that has had previous legal control of a device in the smart home system. This is a potential violation of the principle of least privilege in security concepts, largely attributed to the replay ability retained even after the control scenario was terminated. A detailed scan of other states transition doesn¡¯t seem to throw up other forms of exploitable scenarios.

# Critical Vulnerability report
## Vulnerability 1: Excessive privileges from state s3 to s4
** Threat Level ** : High Risk

** Attack Path ** :
1. Attackers accumulate knowledge through AcceptDeviceShare in state s4
2. Replay the AcceptDeviceShare action in state s5
3. Bypass the UnsharePlug check to reenter privileged state s7

** Repeat steps ** :
Starting from state s0, user1 adds the device then shares to user2 (state s3), where user2 performs the AcceptDeviceShare action to reach state s4. User1 then performs the UnsharePlug operation to reach state s5, but user2 can still replay the AcceptDeviceShare action to regain control of the device (returns to state s4).
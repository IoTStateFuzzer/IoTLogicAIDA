# State Semantic mapping table

| State | Semantic Description |
|-------|----------------------|
| s0    | User1 has not added any devices.|
| s1    | A device has been added by User1. User2 has no permissions as no sharing has occured |
| s2    | This is a deadlock state with no possible operations or progression. Typically occurs after an error or illegal operation |
| s3    | User1 has shared the device control, but User2 has not yet accepted |
| s4    | User1 has shared the device and User2 has accepted the sharing request and has control over the device. User2 has the ability to replay `user2|remote|AcceptDeviceShare` |
| s5    | User1 has unshared the device, revoking User2's control. However, User2's knowledge of `user2|remote|AcceptDeviceShare` remains enabling potential exploits|
| s6    | User1 has removed the device. User2's knowledge of `user2|remote|AcceptDeviceShare` is now useless since there's no device to control |
| s7    | After being unshared (state 5), User1 has shared the device again. However, User2 has not yet accepted |

Firstly, let's verify the correctness of basemodel, we can find that all transitions in basemodel are corresponding with the operation semantics. For example, from `s0` to `s1` when `user1|local|AddDevice / Operation succeeded` and from `s1` to `s3` when `user1|local|SharePlug / Both operations (GET scheduleTips and POST share/devices) succeeded with HTTP 200 and 'success': true`. All transitions follow the rule that an operation is performed by a user in the current state, and if the operation succeeds, it transitions to the next state. All state transitions do not violate the CIA triad and each operation is adequately validated, logically correct, and no security issue in action, therefore basemodel is safe.

Comparing the statefuzzing to basemodel, we need to consider the malicious behaviors (replay attacks) of an attacker (User2) trying to exploit permissions. In the statefuzzing machine, User2 only has the capability to replay `user2|remote|AcceptDeviceShare`. In state `s4`, `s5`, `s6` and `s7`, User2 has the knowledge of `user2|remote|AcceptDeviceShare`. However, even with this knowledge, User2's attempts to gain or promote permissions are unsuccessful. Indeed, despite the knowledge of `user2|remote|AcceptDeviceShare`, the replay attack is rejected, blocking any malicious advancement.

As a result, there is no critical vulnerability detected in the state changes of the `statefuzzing` smart home system. User2 may have the ability to replay the `user2|remote|AcceptDeviceShare` operation, but this does not lead to successful unauthorized control of devices or violation of the CIA triad. Thus, no privacy/security threats are noted.
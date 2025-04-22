# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state. No device or user interactions have taken place.
1 | User1 has legally added a device to the system (HTTP 200).
2 | Null state. Device or share interactions from this state are invalid (NoElement).
3 | User1 has shared a plug, but User2 has not yet accepted. Sharing operations partially failed due to a missing/invalid code (POST share/devices).
4 | User2 has accepted the shared plug, gaining control rights (HTTP 200).
5 | User1 canceled the device sharing or removed the device. User2's access rights to prior shared devices remain in status quo.
6 | User1 has removed the device that User2 had control over. This results in a return to an intermediary state where most operations cannot be completed (NoElement).
7 | User1 has re-shared the plug. User2 can attempt to accept but the POST request will fail if incomplete/missing code is detected (HTTP 200 but 'success': false).

# Critical Vulnerability report
## Vulnerability 1: Unauthorized Device Control Persistence
** Threat Level ** : High Risk

** Attack Path ** :
1. Accumulation of knowledge regarding device sharing status and states where the attacker, user2, (has control temporarily) joins the system by recording a valid device share state.
2. Replay the ¡°user2|remote|AcceptDeviceShare¡± action in state 4.
3. User2 attempts to control the device repeatedly using their API access, even after device sharing is removed/expired.

** Repeat steps ** :
1. From s0, User1 performs the AddDevice action to reach state s1.
2. User1 proceeds to perform the SharePlug action to transition into s3.
3. Now, user2 can perform the ¡°AcceptDeviceShare¡± action transitioning into s4.
4. In state s4, proceed to carry out UnsharePlug by user1, taking us to state s5.
5. Observe that user2 can still replay the ¡°user2|remote|AcceptDeviceShare¡± action maliciously hereafter in state s5, leading back to operational control states.

Summary: In states s4, s5, and s7 where user2 gains control (even temporarily accepted), the device control rights persist improperly after device sharing is canceled (replaying "AcceptDeviceShare").

## Vulnerability 2: Persistence of Device Control Post Device Removal
** Threat Level ** : Medium Risk

** Attack Path ** :
1. User2 exploits replay facility to control device after user1 removes the device.
2. Persist Actions on API interface by user2 even after device states changed.

** Repeat steps ** :
1. User1 adds device (reaching state s1).
2. Share plug (reaching state s3).
3. User2 accepts the share reaching s4. Upon reaching s4, user1 performs device removal, transitioning to s6.
4. In state s6, user2 can still replay DeviceControl illicitly, could cause potential information/control persistence leaks.
5. Violation of data privacy principles akin to replay API actions leading device control cases (noticeable in s5 back to control).

Summary: Unauthorized continued existence and potential control access for `user2` in states s5 and s6 after actions aimed at cancelling such shares devivces.

Therefore, validating extended checks and state-controlled consistency mechanisms and access privileges should carefully preserve, reduce such attacks effectively in real-time transitions across states.
## State Semantic Mapping Table

In statefuzzing:

State number | State semantics
-----|---------
0 | Denotes the initial state, no device added and no sharing occurred.
1 | User 1 has added device locally and has control over the device.
2 | Invalid state with unexecuted operations, no significant changes to user permissions or device status.
3 | User 1 shared the camera locally.
4 | User 1 shared camera locally and user 2 accepted the device share through remote connection.
5 | User 1 removed the device locally from the state of shared camera(3).
6 | User 1 added device locally after removing it in state 5.
7 | User 1 shared the camera locally after adding it in state 6.
8 | User 1 shared the camera locally, User 2 accepted the device share through remote connection after user 1 shared it in state 7.

Comparing the "basemodel" and "statefuzzing", the state
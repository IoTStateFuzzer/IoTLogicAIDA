

# State Semantic mapping table
State | semantic description
-----|---------
0 | Initial state with no devices added. User1 can add a device locally.
1 | Device added by User1. User1 has full control and can share camera/remove device.
2 | Invalid operation state (NoElement outputs). No active device or permissions.
3 | Camera shared by User1. User2 can accept the share via UI (Clickable action).
4 | User2 successfully accepted camera share. User2 has device control privileges.
5 | Device removed by User1. User2 retains knowledge of share acceptance but cannot execute.
6 | Device re-added by User1 after removal. Previous sharing permissions cleared.
7 | Camera re-shared by User1 after device re-addition. New share invitation available.
8 | User2 accepted new camera share. Valid device control permissions for both users.

# Critical Vulnerability report
**No critical vulnerabilities detected**  
The statefuzzing model maintains equivalent security semantics to basemodel. All observed state transition differences correspond to legitimate knowledge set management or state renumbering without introducing privilege escalation paths or information leakage vulnerabilities. Attacker replay attempts are properly invalidated when permissions get revoked or devices are removed.
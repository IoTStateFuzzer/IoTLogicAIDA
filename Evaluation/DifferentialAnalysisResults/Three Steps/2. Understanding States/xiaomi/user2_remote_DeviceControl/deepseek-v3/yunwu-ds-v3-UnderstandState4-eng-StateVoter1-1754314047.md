# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device; user2 has no permissions. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2; user2 has not accepted the invitation yet. |
| 4     | user1 added and shared the device; user2 accepted the share, gaining direct device control permissions. |
| 5     | user1 added, shared, then removed the device; user2's direct device permissions are revoked. |
| 6     | user1 re-added the device after removal; user2 has no permissions (direct sharing was revoked and not re-established). |
| 7     | user1 re-added and re-shared the device; user2 has not accepted the invitation yet. |
| 8     | user1 re-added and re-shared the device; user2 accepted the share, regaining direct device control permissions. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device. |
| 2     | Error state. |
| 3     | user1 added the device and shared it with user2 (direct sharing). |
| 4     | user1 added and shared the device; user2 accepted the share (direct sharing permissions granted). |
| 5     | user1 added, shared, then removed the device (user2's direct sharing permissions revoked). |
| 6     | user1 re-added the device after removal (user2 has no permissions unless reshared). |
| 7     | user1 re-added and reshared the device with user2 after removal. |
| 8     | user1 re-added and reshared the device; user2 accepted the share (direct sharing permissions granted again). |
| 9     | user1 shared the device; user2 accepted and gained control (direct sharing permissions active). |
| 10    | user1 removed the device after user2 had control (user2's permissions revoked). |
| 11    | user1 re-added the device after removal (user2 has no permissions unless reshared). |
| 12    | user1 unshared the device from user2 (user2's direct sharing permissions revoked). |
| 13    | user1 unshared and then reshared the device with user2. |
| 14    | user1 re-added and reshared the device after removal (user2 must re-accept). |
| 15    | user1 unshared, reshared, and then removed the device (user2's permissions revoked). |
| 16    | user1 re-added the device after unsharing and removal (user2 has no permissions unless reshared). |
| 17    | user1 re-added and reshared the device after unsharing and removal. |
| 18    | user1 re-added and reshared the device; user2 accepted the share (direct sharing permissions granted again). |
| 19    | user1 re-added and reshared the device; user2 accepted and gained control (direct sharing permissions active). |
| 20    | user1 unshared the device after user2 had control (user2's permissions revoked). |
| 21    | user1 unshared and then reshared the device with user2 after removal. |
| 22    | user1 re-added and reshared the device; user2 accepted the share (direct sharing permissions granted again). |

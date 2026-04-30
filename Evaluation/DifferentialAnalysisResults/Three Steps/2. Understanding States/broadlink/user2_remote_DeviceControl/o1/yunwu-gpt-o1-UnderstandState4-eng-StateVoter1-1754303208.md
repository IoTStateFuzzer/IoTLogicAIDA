# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. |
| 1     | user1 added the device once; user2 is neither invited nor a member, so no control. |
| 2     | Error state. |
| 3     | user1 added the device once and invited user2 to join the family, but user2 has not accepted. |
| 4     | user1 has no device added; user2 is invited to join the family but has not accepted. |
| 5     | user1 added the device once; user2 scanned the invitation but has not accepted yet. |
| 6     | user1 added the device once; user2 accepted the family invite and has permanent control rights. |
| 7     | user1 added the device once; after multiple invites, user2 accepted and remains a family member with permanent control rights. |
| 8     | user1 has no device; user2 has joined the family and thus has permanent control rights for any future devices. |
| 9     | user1 has no device; after multiple invites, user2 accepted and is now a family member with permanent control rights for future devices. |
| 10    | user1 has no device added; user2 scanned the invitation but has not accepted. |
| 11    | user1 added the device once; user2 was a family member but quit, so user2 lost all control rights. |
| 12    | user1 has no device; user2 was a family member but quit and thus has no membership or control rights. |
| 13    | user1 has no device; user2 is re-invited but has not accepted, so user2 has no control. |
| 14    | user1 added the device once; user2 has been invited multiple times but still has not accepted, so user2 has no control. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0 | Initial state. |
| 1 | user1 has added the device once; user2 is not invited. |
| 2 | Error state. |
| 3 | No device added; user2 is invited but has not accepted membership. |
| 4 | No device added; user2 scanned the invitation code but has not accepted membership. |
| 5 | No device added; user2 is a family member with permanent control for any device user1 adds. |
| 6 | No device added; user2 remains a family member with permanent control for future devices. |
| 7 | user1 has added one device; user2 is a family member with control rights. |
| 8 | user1 has added one device; user2 is a family member with control rights. |
| 9 | No device added; user2 joined as a family member but quit, so no membership now. |
| 10 | user1 has one device added; user2 scanned the invitation code but has not accepted membership. |
| 11 | user1 has one device added; user2’s invitation is pending acceptance. |
| 12 | user1 has one device added; user2 was a family member but quit, so no membership now. |
| 13 | user1 has one device added; user2 scanned the code but has not accepted membership. |
| 14 | No device added; user2 scanned the code but has not accepted membership. |
| 15 | user1 has one device added; user2 is a family member actively controlling it. |
| 16 | user1 removed the device; user2 remains a family member and will control any re-added device. |
| 17 | user1 removed the device and user2 quit the home, so user2 is no longer a family member. |
| 18 | user1 re-added the device; user2 quit the home and is not a family member. |
| 19 | user1 has one device added; user2 quit the home and is no longer a member. |
| 20 | user1 has one device added; user2 quit home, scanned again, but has not accepted or regained membership. |
| 21 | user1 re-added the device; user2 quit the home, scanned the code, but has not accepted membership. |
| 22 | No device is present; user2 quit the home and scanned a code without regaining membership. |
| 23 | No device is present; user2 is re-invited after quitting, but has not accepted. |
| 24 | user1 has re-added the device; user2 has been re-invited but has not accepted. |
| 25 | user1 has one device added; user2 quit home, was re-invited, but has not accepted membership. |
| 26 | user1 removed the device; user2 remains a family member with no device to control. |
| 27 | user1 removed the device; user2 then quit home, losing membership. |
| 28 | user1 re-added the device; user2 quit home, so user2 is not a member. |
| 29 | user1 re-added the device; user2 remains a family member with control rights. |
| 30 | user1 has one device added; user2 is a family member actively controlling it. |
| 31 | user1 has one device added; user2 quit the home, so user2 is no longer a member. |
| 32 | user1 re-added the device; user2 remains a family member with control rights. |


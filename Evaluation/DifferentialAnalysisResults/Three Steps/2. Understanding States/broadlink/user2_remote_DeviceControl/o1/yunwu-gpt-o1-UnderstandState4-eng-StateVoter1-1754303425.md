# Base Model
| State | Final Semantic Description                                                                                                                |
|-------|-------------------------------------------------------------------------------------------------------------------------------------------|
| s0    | Initial state with no device added; user2 is not invited.                                                                                 |
| s1    | user1 has added one device; user2 is not invited and has no control.                                                                      |
| s2    | Error state.                                                                                                                              |
| s3    | user1 has added one device and invited user2, but user2 has not accepted.                                                                 |
| s4    | No device is added; user2 is invited but has not accepted.                                                                                |
| s5    | user1 has added one device; user2 is invited, scanned the code, but has not completed acceptance.                                         |
| s6    | user1 has added one device; user2 accepted the family invitation, gaining permanent control under family rules.                           |
| s7    | user1 has added one device; user2 accepted the family invitation (after multiple invites) and retains permanent control.                  |
| s8    | No device is added; user2 is a fully accepted family member and will have permanent control over any future device additions.             |
| s9    | No device is added; user2 eventually accepted (after multiple invites) and is a family member with permanent control over any future device. |
| s10   | No device is added; user2 scanned the invitation code but never completed acceptance and has no control.                                  |
| s11   | user1 has added one device; user2 had family membership but quit, losing all control.                                                     |
| s12   | No device is added; user2 was previously family but quit, losing membership and any control.                                              |
| s13   | No device is added; user2 received multiple invitations, scanned but never accepted.                                                      |
| s14   | user1 has added one device; user2 was re-invited and scanned but never accepted, obtaining no control.                                    |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state. No device added; user2 not invited. |
| 1     | user1 has added one device; user2 is not invited and has no access. |
| 2     | Error state. |
| 3     | No device added (user1 has 0 devices); user2 is invited but has not accepted. |
| 4     | No device added; user2 has scanned the invitation code but not completed acceptance. |
| 5     | No device added; user2 is a family member with permanent control rights for future devices. |
| 6     | No device added; user2 went through multiple invites but ultimately gained permanent family member rights. |
| 7     | user1 has added one device; user2 is a family member with permanent control rights to that device. |
| 8     | user1 has added one device; user2 is a family member with permanent control rights. |
| 9     | No device added; user2 was a family member but quit and lost membership. |
| 10    | user1 has one device (first addition); user2 is invited, has scanned the code, but not accepted. |
| 11    | user1 has one device; user2 is invited but has not accepted. |
| 12    | user1 has one device; user2 joined as a family member but then quit, losing membership. |
| 13    | user1 has one device; user2 was re-invited or scanned again but has not accepted membership. |
| 14    | No device added (user1 has 0 devices); user2 remains invited or has scanned again but not accepted. |
| 15    | user1 has one device; user2 is a family member actively controlling the device. |
| 16    | No devices remain; user2 remains a family member with permanent rights to any future devices. |
| 17    | No device remains; user2 was a family member but quit the home and lost membership. |
| 18    | user1 has re-added the device (second addition); user2 has quit the family and lost membership. |
| 19    | user1 has one device; user2 was a family member but quit, so no membership remains. |
| 20    | user1 has one device; user2 quit the family, scanned a code again, but remains outside the family. |
| 21    | user1 has the device (second addition); user2 quit the family, scanned a code afterward, but did not rejoin. |
| 22    | No devices remain; user2 quit the family and scanned a code but remains a non-member. |
| 23    | No devices remain; user2 previously quit the family and was invited again but has not accepted. |
| 24    | user1 re-added the device (second addition); user2 quit the family earlier and is newly invited but hasn't accepted. |
| 25    | user1 has one device; user2 quit and was re-invited but has not accepted. |
| 26    | No device remains; user2 remains a family member with rights to any future device. |
| 27    | No device remains; user2 was a family member but quit, losing membership. |
| 28    | user1 has re-added the device (second addition); user2 was a family member but quit, losing membership. |
| 29    | user1 has re-added the device (second addition); user2 remains a family member with automatic control. |
| 30    | user1 has one device; user2 is a family member actively controlling that device. |
| 31    | user1 has one device; user2 was a family member but quit, losing membership. |
| 32    | user1 has re-added the device (second addition); user2 remains a family member with control rights. |


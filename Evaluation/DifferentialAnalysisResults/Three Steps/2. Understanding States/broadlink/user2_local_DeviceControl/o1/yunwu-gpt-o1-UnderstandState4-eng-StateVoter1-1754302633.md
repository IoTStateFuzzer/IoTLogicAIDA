# Base Model
| State | Semantic Description |
|-------|----------------------|
| s0  | Initial state. No device added; user2 has no membership or control. |
| s1  | user1 has added the device once; user2 is not invited and has no control. |
| s2  | Error state. |
| s3  | user1 has added the device once; user2 is invited as a family member but has not accepted. |
| s4  | No device added; user2 is invited as a family member but has not accepted. |
| s5  | user1 has added the device once; user2 scanned the code but has not accepted the family invite. |
| s6  | user1 has added the device once; user2 accepted the family invitation and has permanent control rights. |
| s7  | user1 has added the device once; user2 accepted repeated invitations and has permanent control rights. |
| s8  | No device added; user2 accepted the family invitation and is a family member with permanent control for future devices. |
| s9  | No device added; user2 accepted a repeated family invitation and now has permanent control rights for future devices. |
| s10 | No device added; user2 scanned the code but has not accepted the family invite. |
| s11 | user1 has added the device once; user2 joined as family but quit, losing membership and control. |
| s12 | No device added; user2 joined as family but quit, losing membership and control. |
| s13 | No device added; user2 scanned a renewed invite but has not accepted, leaving membership pending. |
| s14 | user1 has added the device once; user2 scanned a renewed invite but has not accepted, so user2 has no control rights. |

# Divergent Model
| State | Semantic Description |
|-------|----------------------|
| s0  | Initial state. No device is added; user2 is not invited. |
| s1  | user1 has added the device once; user2 is not invited. |
| s2  | Error state. |
| s3  | No device is added; user2 is invited but has not accepted family membership. |
| s4  | No device is added; user2 scanned the invitation code but has not accepted family membership. |
| s5  | No device is added; user2 has accepted the invitation and is now a family member. |
| s6  | No device is added; user2 remains a family member after multiple invitations. |
| s7  | One device is added; user2 is a family member with control rights. |
| s8  | One device is added; user2 is a family member with control rights. |
| s9  | No device is added; user2 was a family member but quit, so user2 no longer has membership. |
| s10 | One device is added; user2 is invited but has not accepted membership. |
| s11 | One device is added; user2 is invited but has not accepted membership. |
| s12 | One device is added; user2 was a family member but quit and now has no membership or control. |
| s13 | One device is added; user2 scanned an invitation but has not accepted, so is not a family member. |
| s14 | No device is added; user2 scanned the invitation but has not accepted membership. |
| s15 | One device is added; user2 is a family member actively controlling it. |
| s16 | The device was removed; user2 remains a family member with rights if re-added. |
| s17 | The device was removed; user2 then quit the family and is no longer a member. |
| s18 | The device was removed and re-added; user2 then quit the family and has no membership or control. |
| s19 | One device is added; user2 quit the family and is no longer a member. |
| s20 | One device is added; user2 quit the family and scanned a code later but did not re-accept, remaining outside. |
| s21 | The device was removed and re-added; user2 quit the family and scanned a code without re-accepting, so not a member. |
| s22 | No device is present; user2 quit the family and scanned a code but remains outside the membership. |
| s23 | No device is present; user2 quit but was re-invited and has not accepted. |
| s24 | The device has been re-added (two total additions); user2 quit but was re-invited and has not accepted. |
| s25 | One device is added; user2 quit the family, was re-invited, and has not accepted. |
| s26 | No device is present; user2 remains a family member and will have control if re-added. |
| s27 | No device is present; user2 quit the family and no longer has membership. |
| s28 | The device was re-added; user2 quit the family and no longer has membership or control. |
| s29 | The device was removed and re-added; user2 remains a family member with control rights. |
| s30 | One device is added; user2 is a family member with control rights. |
| s31 | One device is added; user2 quit the family and is no longer a member. |
| s32 | The device was removed and re-added; user2 remains a family member with control rights. |


# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0    | Initial state: no device added by user1; user2 is not invited, not a family member, and has no control permissions. |
| s1    | user1 has added the device once; user2 is not invited and has no control permissions. |
| s2    | Error state. |
| s3    | user1 has added the device once and invited user2 as family member; user2 has not accepted the invitation yet and therefore has no control permissions. |
| s4    | user1 invited user2 as family member without adding any device; user2 has not accepted the invitation and has no control permissions. |
| s5    | user1 has added the device once and invited user2 as family member; user2 scanned the invitation but has not accepted yet and has no control permissions. |
| s6    | user1 added the device once and user2 accepted the family invitation, becoming a family member with permanent control rights over all user1 devices, independent of device addition count. |
| s7    | user1 added the device once and invited user2 twice as family member; user2 accepted the invitation and holds family member status with permanent control rights regardless of device addition count or invitation redundancy. |
| s8    | user1 invited user2 as family member without adding a device; user2 accepted the invitation and is a family member with permanent control rights over user1’s devices, device addition count being irrelevant. |
| s9    | user1 invited user2 twice as family member without device addition; user2 accepted and holds family member status with permanent control rights, unaffected by invitation repetition. |
| s10   | user1 invited user2 as family member without adding device; user2 scanned invitation but has not accepted, thus has no control permissions. |
| s11   | user1 added the device once, user2 accepted the family invitation but then quit the family membership; user2 no longer has any control permissions. |
| s12   | user1 invited user2 as family member without device addition; user2 accepted then quit family membership and no longer has control permissions. |
| s13   | user1 invited user2 twice as family member without device added; user2 has not accepted any invitation and therefore has no control permissions. |
| s14   | user1 added the device once and invited user2 twice as family member; user2 has not accepted any invitation yet and has no control permissions. |

# Divergent Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0    | Initial state: user1 has not added any device; user2 is not invited, not a family member, and has no permissions. |
| s1    | user1 has added the device once; user2 has not been invited and has no permissions. |
| s2    | Error state. |
| s3    | user1 invited user2 as a family member; user2 has neither scanned the invitation QR code nor accepted the invitation yet; user2 has no control or membership. |
| s4    | user1 invited user2 as family member; user2 scanned the QR code but has not accepted the invitation; user2 is not a family member and has no control permissions. |
| s5    | user1 invited user2 as family member; user2 scanned and manually accepted the invitation; user2 is now a family member with permanent control rights over all user1's devices, regardless of device additions. |
| s6    | user1 sent multiple invitations to user2 as family member; user2 accepted one invitation and retains permanent family member status with control rights over all user1 devices. |
| s7    | user1 added the device once and invited user2 multiple times as family member; user2 accepted the invitation and holds family member status with permanent control permissions on all user1 devices. |
| s8    | user1 added the device once and invited user2 as family member; user2 scanned and accepted the invitation; user2 has permanent control rights over user1's devices. |
| s9    | user2 accepted family membership and control, then quit the home; user2 no longer is a family member and has no control permissions. |
| s10   | user1 added device once and invited user2 as family member; user2 scanned the QR code but has not accepted invitation yet; user2 has no family membership or control. |
| s11   | user1 added device once and invited user2; user2 has not scanned or accepted the invitation; no family membership or permissions granted. |
| s12   | user2 accepted family invitation, then quit home; user2 lost family membership and control permissions. |
| s13   | user1 added device once and invited user2 twice as family member; user2 scanned but did not accept the second invitation; user2 is not a family member and has no control. |
| s14   | user1 invited user2 twice as family member; user2 scanned once but never accepted any invitation; user2 has no family membership or control permissions. |
| s15   | user1 added device once and invited user2 twice; user2 accepted invitation and actively controls the device as a family member with permanent control rights. |
| s16   | user1 added device once and invited twice; user2 accepted invitation and controlled device; user1 then removed the device; user2 remains a family member with permanent control rights, but no device currently added. |
| s17   | After device removal, user2 quit home; user2 is no longer family member and has no control permissions; no device is present. |
| s18   | user1 re-added the device after removal; user2 quit home previously; user2 is not currently a family member and has no permissions. |
| s19   | user2 quit home after accepting invitation and controlling device; user2 no longer family member and has no control rights; device remains added once. |
| s20   | user2 quit home after acceptance and control, then scanned QR code again but has not accepted new invitation; no family membership or control permissions currently. |
| s21   | user1 removed and re-added device once; user2 quit home, scanned QR code but did not accept invitation; user2 has no family membership or control permissions. |
| s22   | user1 removed device; user2 quit home, scanned but did not accept new invitation; no permissions granted; no device currently added. |
| s23   | After device removal, user2 quit home, scanned, and was reinvited by user1; user2 has scanned but not accepted invitation yet; no control or membership. |
| s24   | user1 re-added device after removal; user2 quit home, rescanned, reinvited by user1; user2 has scanned but not accepted; no permissions currently. |
| s25   | user2 quit home after acceptance and control, rescanned QR, and was reinvited by user1; user2 has not accepted new invitation; no control or family membership currently. |
| s26   | user1 added device once and invited user2; user2 accepted invitation and controlled device; user1 removed device; user2 remains family member per family priority rule but has no current device control as device is absent. |
| s27   | User2 quit home after device removal; user2 lost family membership and all control permissions; no device currently present. |
| s28   | After removal and re-addition of device by user1, user2 is not family member and has no control permissions due to prior quit home. |
| s29   | User1 removed and re-added device once; user2 previously accepted invitation and did not quit home; user2 retains family member status with permanent control rights despite device removal and re-addition. |
| s30   | user1 added device once; user2 accepted invitation and currently controls device as family member with permanent control rights. |
| s31   | user2 accepted invitation and controlled device; later quit home; user2 lost family membership and all control permissions; device remains added. |
| s32   | user1 removed and re-added device; user2 remains family member with permanent control rights, consistent with family priority rule through device removal and re-addition. |


# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| 0     | Initial state: No device added by user1 and user2 not invited or affiliated. |
| 1     | user1 has added the device once; user2 not invited or recognized, thus no permissions. |
| 2     | Error state. |
| 3     | user1 added the device once and invited user2 to become a family member; user2 has not accepted the invitation yet and holds no control permissions. |
| 4     | user1 invited user2 to become a family member without adding the device; user2 has not accepted yet and holds no control permissions. |
| 5     | user1 added the device once and invited user2; user2 scanned the invitation but has not accepted yet, so no permissions granted. |
| 6     | user1 added the device once; user2 accepted the family member invitation and has permanent control rights over all user1 devices regardless of device addition. |
| 7     | user1 added the device once and sent two family member invitations; user2 accepted and holds permanent family control over all user1 devices. |
| 8     | user1 invited user2 as family member without device addition; user2 accepted and has permanent family control rights even though no device is added yet. |
| 9     | user1 invited user2 twice as family member without device addition; user2 accepted and retains permanent family control rights. |
| 10    | user1 invited user2 as family member without device addition; user2 scanned the invitation but has not accepted yet and has no permissions. |
| 11    | user1 added the device once and invited user2 as family member; user2 accepted but later quit the family, losing all control permissions despite device presence. |
| 12    | user1 invited user2 as family member without device addition; user2 accepted but later quit the family, losing all control permissions. |
| 13    | user1 invited user2 twice as family member without device addition; user2 scanned but has not accepted yet and holds no permissions. |
| 14    | user1 added the device once and invited user2 twice as family member; user2 scanned but has not accepted yet, therefore no control permissions are granted. |

# Divergent Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0    | Initial state with no device added or sharing initiated. |
| s1    | user1 has added the device once; user2 is not invited or a family member and has no permissions. |
| s2    | Error state. |
| s3    | user1 invited user2 to become a family member; user2 is invited but has neither scanned nor accepted the invitation, so no permissions granted. |
| s4    | user1 invited user2; user2 scanned the QR code but has not accepted the invitation yet, so no permissions granted. |
| s5    | user1 invited user2; user2 scanned and accepted the invitation, becoming a family member with permanent control rights over all user1’s devices. |
| s6    | user1 re-invited user2 before user2 accepted; user2 ultimately accepted and is a family member with permanent control rights. |
| s7    | user1 added the device once and invited user2 twice; user2 scanned and accepted the invitation and is a family member with permanent control over all user1’s devices. |
| s8    | user1 added the device once and invited user2; user2 scanned and accepted, becoming a family member with permanent control over all user1’s devices. |
| s9    | user1 invited user2 who scanned and accepted but then quit the family; user2 is no longer a family member and has no control. |
| s10   | user1 added the device once and invited user2; user2 scanned but has not accepted the invitation yet; user2 has no control. |
| s11   | user1 added the device once and invited user2; user2 neither scanned nor accepted; user2 has no control. |
| s12   | user1 added the device once and invited user2; user2 scanned and accepted then quit the family; user2 is no longer family and has no control. |
| s13   | user1 added the device once and invited user2 twice; user2 scanned but has not accepted the latest invitation; user2 has no control. |
| s14   | user1 invited user2 twice; user2 scanned but has not accepted either invitation; no permissions granted. |
| s15   | user1 added the device once and invited user2 twice; user2 scanned, accepted, and has permanent control as a family member over all user1’s devices. |
| s16   | user1 added the device once and invited user2 twice; user2 accepted and controlled the device; user1 then removed the device; user2 remains a family member with permanent control rights, but device is absent so no active control. |
| s17   | Same as s16 but user2 quit the family after device removal; user2 no longer family and has no control. |
| s18   | user1 removed then re-added the device once; user2 quit the family after removal and holds no control or family membership despite re-addition. |
| s19   | user1 added the device once; user2 accepted the family invitation and controlled the device but then quit the family; user2 lost family membership and control. |
| s20   | user1 added the device once; user2 accepted the family invitation and controlled the device but quit the family and rescanned QR code without accepting a new invitation; no control granted. |
| s21   | user1 removed and re-added the device once; user2 quit the family and rescanned QR code without accepting a new invitation; no permissions granted. |
| s22   | user1 removed the device; user2 quit the family and rescanned QR code without acceptance; no control or permissions granted. |
| s23   | User1 removed the device; user2 quit the family, rescanned QR code; user1 re-invited user2; user2 is invited but has not accepted again and has no control. |
| s24   | User1 removed then re-added the device; user2 quit the family, rescanned QR code; user1 re-invited user2; user2’s invitation acceptance is pending; no control granted. |
| s25   | user2 quit the family and rescanned QR code after user1 re-invited user2; user2 has not accepted yet and has no control. |
| s26   | user1 added the device once and invited user2; user2 accepted and controlled the device; user1 removed the device; user2 remains a family member with permanent control rights over user1’s devices, but device is absent so no active control. |
| s27   | Same as s26 but user2 quit the family after device removal; user2 no longer family and has no control. |
| s28   | user1 removed and re-added the device; user2 quit the family after removal; user2 has no family membership or control despite re-addition. |
| s29   | user1 removed then re-added the device after user2 accepted previously; user2’s current family membership and control depend on whether user2 quit the family after removal; if quit, no control; otherwise, family membership and control persist. |
| s30   | user1 added the device once; user2 accepted the family invitation and currently controls the device as a family member. |
| s31   | user2 accepted and controlled the device as a family member but then quit the family; user2 currently has no family membership or permissions. |
| s32   | user1 removed and re-added the device; user2 accepted the family invitation and remains a family member with permanent control rights over all user1’s devices. |


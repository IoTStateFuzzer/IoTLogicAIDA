# Base Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0 | Initial state. user1 has not added any device, no invitations issued; user2 is not invited and has no permissions. |
| s1 | user1 has added the device once; user2 is not invited and has no permissions. |
| s2 | Error state indicating an invalid or inconsistent action sequence. |
| s3 | user1 added the device once and invited user2 as a family member; user2 has not accepted the invitation yet and thus has no control permissions. |
| s4 | user1 invited user2 as a family member without adding the device; user2 is invited but has not accepted, and user2 has no control permissions. |
| s5 | user1 added the device once and invited user2 as family; user2 has scanned the invitation but not accepted it yet, so no control permissions are granted. |
| s6 | user1 added the device once and invited user2; user2 accepted the family membership invitation, becoming a family member with permanent control rights over all user1’s devices, independent of device addition count. |
| s7 | user1 added the device once and invited user2 twice as family; user2 accepted and remains a family member with permanent control rights over all user1’s devices; multiple invitations before acceptance do not affect status. |
| s8 | user1 invited user2 as family without adding the device; user2 scanned and accepted the invitation, becoming a family member with permanent control rights regardless of device addition. |
| s9 | user1 invited user2 twice as family without adding the device; user2 accepted the invitation and is a family member with permanent control rights; multiple invitations do not change status. |
| s10 | user1 invited user2 as family without adding the device; user2 scanned the invitation QR code but has not accepted yet; user2 has no control permissions. |
| s11 | user1 added the device once and invited user2; user2 accepted the family membership but then quit, losing family membership and all control permissions. |
| s12 | user1 invited user2 as family without device addition; user2 accepted the invitation but later quit family membership, losing all control permissions. |
| s13 | user1 invited user2 twice as family without adding the device; user2 scanned the invitation but has not accepted; user2 remains invited without any control permissions. |
| s14 | user1 added the device once and invited user2 twice as family; user2 scanned the invitation but has not accepted; user2 remains invited without control permissions. |

# Divergent Model
| State | Final Consolidated Semantic Description |
|-------|------------------------------------------|
| s0    | Initial state; no device added by user1; user2 has no family membership or control permissions. |
| s1    | user1 has added the device once; user2 has no invitation, family membership, or control permissions. |
| s2    | Error state. |
| s3    | user1 invited user2 to become a family member; user2 has not scanned QR code nor accepted invitation; user2 is not family member and has no control permissions. |
| s4    | user1 invited user2; user2 scanned QR code but has not accepted the invitation; user2 is not family member and has no control permissions. |
| s5    | user1 invited user2; user2 scanned QR code and accepted invitation; user2 is a family member with permanent control rights independent of device presence or sharing. |
| s6    | user1 invited user2 twice before acceptance; user2 scanned QR code and accepted once; user2 is family member with permanent control rights. |
| s7    | user1 added the device once and invited user2 twice; user2 scanned and accepted invitation; user2 has family member status with permanent control rights over the device. |
| s8    | user1 added the device once and invited user2 once; user2 scanned and accepted invitation; user2 is family member with permanent control rights. |
| s9    | user1 invited user2; user2 scanned, accepted invitation, then quit family/home; user2 no longer family member and has no control permissions. |
| s10   | user1 added the device once and invited user2; user2 scanned QR code but has not accepted invitation; user2 has no control permissions. |
| s11   | user1 added the device once and invited user2; user2 neither scanned nor accepted invitation; user2 has no control permissions. |
| s12   | user1 added device and invited user2; user2 scanned, accepted invitation, then quit family; user2 lost family member status and control permissions. |
| s13   | user1 added the device once and invited user2 twice; user2 scanned but has not accepted any invitation; user2 has no control permissions. |
| s14   | user1 invited user2 twice; user2 scanned but has not accepted invitation; user2 is not family member and has no control permissions. |
| s15   | user1 added the device once and invited user2 twice; user2 scanned, accepted invitation, and currently controls device; user2 is family member with permanent control rights. |
| s16   | As s15, but user1 removed the device afterward; device count zero; user2 remains family member with permanent control rights but no device currently to control. |
| s17   | After device removal, user2 quit family; user2 has no family membership or control permissions; device count zero. |
| s18   | user1 removed and re-added device after user2 quit family; user2 is not family member and has no control permissions on the device. |
| s19   | user2 quit family/home but device remains; user2 is not family member and has no control permissions despite device presence. |
| s20   | After quitting family, user2 scanned QR code again but has not accepted invitation; user2 has no control permissions. |
| s21   | After device removed and re-added, and user2 quit family and scanned QR code again without acceptance; user2 has no control permissions. |
| s22   | After device removed and user2 quit family, user2 scanned QR again but has not accepted invitation; user2 has no control permissions. |
| s23   | Same as s22 but user1 sent a new invitation; user2 scanned but has not yet accepted; user2 has no control permissions. |
| s24   | After device cycle and user2 quit family, scanned QR again, then invitation resent; user2 not accepted; no control permissions. |
| s25   | user2 quit family, scanned QR again, and was invited once more; no acceptance yet; user2 has no control permissions. |
| s26   | user1 added device and invited user2; user2 accepted and controls device; device present and user2 family member with permanent control rights. |
| s27   | As s26 but user1 removed device afterward; device count zero; user2 remains family member but no device control currently. |
| s28   | After device removed, user1 re-added device; user2 quit family; user2 is not family member and has no control permissions. |
| s29   | user1 re-added device after removal; user2 had accepted before but quit family; user2 has no control permissions on re-added device. |
| s30   | user1 added device once, invited user2; user2 accepted and controls device; user2 is active family member with permanent control rights. |
| s31   | As s30 but user2 quit family; user2 lost family membership and all control permissions despite device presence. |
| s32   | user1 removed then re-added device after user2 accepted and controlled device; user2 remains family member with permanent control rights independent of device removal and re-addition. |


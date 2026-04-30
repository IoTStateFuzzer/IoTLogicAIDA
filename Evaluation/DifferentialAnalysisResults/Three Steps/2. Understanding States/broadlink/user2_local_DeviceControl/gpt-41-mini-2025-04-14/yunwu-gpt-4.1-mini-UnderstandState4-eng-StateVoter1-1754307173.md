# Base Model
| State | Semantic Description |
|-------|----------------------|
| 0     | Initial state: user1 has not added any device, no invitations sent, and user2 has no permissions or family status. |
| 1     | user1 has added the device once; user2 is not invited, not a family member, and has no control permissions. |
| 2     | Error state. |
| 3     | user1 has added the device once and invited user2 as family member; user2 has not yet accepted the invitation and has no control permissions. |
| 4     | user1 invited user2 as family member without adding any device; user2 has not accepted and therefore has no control permissions. |
| 5     | user1 added the device once and invited user2 as family member; user2 scanned QR code but has not accepted the invitation, so no control permissions are granted. |
| 6     | user1 added the device once; user2 accepted the family member invitation and thus has permanent control rights over all user1 devices regardless of device addition or removal. |
| 7     | user1 added the device once and invited user2 twice; user2 accepted and is a family member with permanent control rights over all user1 devices. |
| 8     | user1 invited user2 as family member without adding any device; user2 accepted and is a family member with permanent control rights, effective when devices are added. |
| 9     | user1 invited user2 twice as family member without device added; user2 accepted after the second invitation and has permanent control rights upon device addition. |
| 10    | user1 invited user2 as family member without device added; user2 scanned QR code but has not accepted the invitation, so no control permissions exist. |
| 11    | user1 added the device once; user2 accepted family membership but subsequently quit, losing family status and all control permissions. |
| 12    | user1 invited user2 as family member without device; user2 accepted then quit family membership and no longer retains any permissions or family rights. |
| 13    | user1 invited user2 twice as family member without device and no acceptance; user2 is not family and has no control permissions. |
| 14    | user1 added the device once and invited user2 twice; user2 scanned QR code but did not accept, so user2 is not family and has no control permissions. |

# Divergent Model
| State | Final Semantic Description |
|-------|----------------------------|
| s0    | Initial state with no device added; user2 is not invited and has no permissions. |
| s1    | user1 has added the device once; user2 is not invited and has no permissions. |
| s2    | Error state. |
| s3    | user1 invited user2 to become a family member; user2 has not yet scanned or accepted the invitation and holds no control permissions. |
| s4    | user1 invited user2 as family member; user2 scanned the invitation QR code but has not accepted yet and thus has no control permissions. |
| s5    | user1 invited user2 as family member; user2 scanned and accepted the invitation, becoming a family member with permanent control rights over user1’s devices, regardless of device addition or removal. |
| s6    | user1 sent multiple family invitations to user2; user2 accepted at least one and is a family member with permanent control over user1’s devices. |
| s7    | user1 added the device once and invited user2 multiple times; user2 accepted once, is a family member, and has permanent control over user1’s devices. |
| s8    | user1 added the device once and invited user2 once; user2 accepted the family invitation and has permanent control over user1’s devices. |
| s9    | user2 quit family membership after accepting the invitation; user2 no longer has family status or control permissions. |
| s10   | user1 added the device once and invited user2; user2 scanned but has not accepted the family invitation, thus has no control permissions. |
| s11   | user1 added the device once and invited user2; user2 has not scanned or accepted the invitation and holds no permissions. |
| s12   | user2 accepted family invitation then quit family membership; user2 lost all control permissions regardless of device addition. |
| s13   | user1 added the device once and invited user2 multiple times; user2 scanned invitation at least once but never accepted; user2 has no family membership or control permissions. |
| s14   | user1 invited user2 multiple times; user2 scanned invitation at least once but never accepted; user2 lacks family membership and control permissions. |
| s15   | user1 added the device once and invited user2 multiple times; user2 accepted once, is family member, and currently controls the device with permanent permissions. |
| s16   | user1 added the device once, invited user2 multiple times; user2 accepted invitation and is family member with permanent control even after user1 removed the device instance (zero devices bound). |
| s17   | user1 added device, invited user2 multiple times; user2 accepted then quit family membership after device removal; user2 lost all control permissions. |
| s18   | user1 removed device, then re-added it; user2 quit family membership before or after re-adding; user2 has no family membership or control permissions. |
| s19   | user2 quit family membership after controlling device; user2 no longer has control or family membership, even while device remains bound. |
| s20   | user2 quit family membership, rescanned QR code but has not accepted new invitation; user2 holds no permissions. |
| s21   | user1 removed and re-added device; user2 quit family membership, rescanned QR but has not accepted new invitation; user2 holds no permissions. |
| s22   | user1 removed device; user2 quit family prior to rescanning and has not accepted any new invitation; user2 has no control permissions. |
| s23   | user2 quit family, rescanned after device removal; user1 reinvited user2; user2 has not accepted new invitation and holds no permissions. |
| s24   | user1 removed and re-added device; user2 quit family, rescanned, and was reinvited by user1; user2 has not accepted latest invitation and holds no permissions. |
| s25   | user2 quit family, rescanned, and user1 reinvited; user2 has not accepted invitation again and thus has no permissions. |
| s26   | user1 added device once; user2 accepted family invitation and is a family member with permanent control permissions even after user1 removed the device. |
| s27   | user2 accepted family invitation but later quit family membership after device removal; user2 no longer has family membership or control permissions. |
| s28   | user1 removed device then re-added it; user2 accepted family invitation prior to quitting family; user2 no longer has permissions after quitting. |
| s29   | user1 removed and re-added device; user2 accepted previously but quit family afterwards; user2 holds no control or family membership. |
| s30   | user1 added device once; user2 accepted family invitation and currently has control permissions as family member. |
| s31   | user2 accepted family invitation, controlled device, then quit family membership; user2 loses all control permissions despite device being present. |
| s32   | user1 added device once, removed it, then re-added it; user2 is family member who accepted invitation and maintains permanent control unaffected by device removal and re-addition. |


# MCP Software-Work Tool Adapter V1

**Superseded.** The provider-side MCP tool `tos_service_software_work` that
this document described was retired on 2026-11-08: it was built on the escrow
execution Gate and was removed with the escrow rail in `execution/` commit
`0d0dfc22d357c04ef128e4d1f68fde7d09d43c5c` (`execution/pkg/mcpadapter`, its
public HTTP boundary and the cross-transport acceptance test); the Gate itself
was removed in `protocol/` commit `b9ad8e17`. No implementation conforms to
it.

The current MCP design is the buyer-side adapter on the Service Actor rail,
[`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md). The retired text stays
in git history: this file as it was before the commit that replaced it.

# asr_nsg_handler.py
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import logging
import re

from nsg_rules import PlatformAllowRule, NsgRuleOperations
from azure_services import NsgManager, SubnetManager, AzureNetworkService, AzureResourceManager

HTTPS_PORTS: List[str] = ["443"]
# Keep ASR priorities a little higher than your SQLMI/PGSQL (501/502) to avoid conflicts.
ASR_DEDICATED_PRIORITY = 510
ASR_SHARED_PRIORITY = 511

@dataclass
class NsgInfo:
    nsg_id: Optional[str]
    nsg_name: Optional[str]
    vnet_rg: Optional[str]

class AsrNsgRulesHandler:
    """
    Creates/removes NSG rules for Azure Site Recovery (ASR)
    using the conditions from the requirements screenshot.

    Model used:
      - We attach rules to the **VM application subnet NSG** in each region.
      - Sources/Destinations are:
          * the opposite region's VM subnet CIDR, and/or
          * private endpoint IPs (RSV PE, Cache Storage Account PE) in the same region,
        always on port 443.

    Assumptions (adjust if your naming differs):
      - App VM subnets contain the application name and are **not** PE subnets.
      - Private Endpoints contain recognizable names:
          * RSV  : name contains 'rsv' (case-insensitive)
          * CACHE: name contains 'cache' or 'storage' (case-insensitive)
      - AzureNetworkService exposes network_client with:
          network_client.subnets.list(rg, vnet)
          network_client.private_endpoints.list(rg)

    This handler is idempotent by priority+name; it also supports destroy mode.
    """

    def __init__(
        self,
        manager: NsgManager,
        operations: NsgRuleOperations,
        subnet_manager: SubnetManager,
        azure_service: AzureNetworkService,
        azure_resource_manager: AzureResourceManager,
    ) -> None:
        self.manager = manager
        self.operations = operations
        self.subnet_manager = subnet_manager
        self.azure_service = azure_service
        self.azure_resource_manager = azure_resource_manager

    # ----------------------------
    # Public entry point
    # ----------------------------
    def process_rules(self, destroy_mode: bool) -> None:
        """
        Orchestrates dedicated + shared ASR rules for the two regions we support.
        """
        regions = ["cus", "eus2"]  # Adjust if you support more/others
        region_ctx = self._discover_region_context(regions)

        # Dedicated rules
        # 1) On CUS VM subnet NSG:
        #    - Source: [EUS2 VM subnet CIDR, CUS RSV PE IPs]
        #    - Dest  : CUS VM subnet CIDR
        # 2) On EUS2 VM subnet NSG:
        #    - Source: [CUS VM subnet CIDR, EUS2 RSV PE IPs]
        #    - Dest  : EUS2 VM subnet CIDR
        for region in regions:
            other = "eus2" if region == "cus" else "cus"
            self._apply_or_remove_rule(
                rule_group="asr-dedicated",
                current=region_ctx.get(region),
                other=region_ctx.get(other),
                priority=ASR_DEDICATED_PRIORITY,
                ports=HTTPS_PORTS,
                # dedicated uses RSV PE IPs from the *current* region + the *other* region's VM subnet
                sources=self._merge(
                    [self._cidr_or_none(region_ctx.get(other, {}).get("vm_subnet"))],
                    region_ctx.get(region, {}).get("rsv_pe_ips", []),
                ),
                destination_cidr=self._cidr_or_none(region_ctx.get(region, {}).get("vm_subnet")),
                destroy_mode=destroy_mode,
                name_suffix=f"dedicated-{region}",
            )

        # Shared rules
        # Per the screenshot:
        #   1) On CUS VM NSG: Source = [CUS Cache PE IPs, CUS VM subnet], Dest = CUS RSV PE IPs
        #   2) On CUS VM NSG: Source = [CUS VM subnet], Dest = CUS Cache PE IPs
        #   3) On EUS2 VM NSG: Source = [EUS2 Cache PE IPs, EUS2 VM subnet], Dest = EUS2 RSV PE IPs
        #   4) On EUS2 VM NSG: Source = [EUS2 VM subnet], Dest = EUS2 Cache PE IPs
        for region in regions:
            ctx = region_ctx.get(region, {})
            vm_cidr = self._cidr_or_none(ctx.get("vm_subnet"))
            rsv_ips = ctx.get("rsv_pe_ips", [])
            cache_ips = ctx.get("cache_pe_ips", [])

            # 1 & 3: VM + CACHE → RSV
            self._apply_or_remove_rule(
                rule_group="asr-shared-vm-cache-to-rsv",
                current=ctx,
                other=None,
                priority=ASR_SHARED_PRIORITY,
                ports=HTTPS_PORTS,
                sources=self._merge([vm_cidr], cache_ips),
                destination_ips=rsv_ips,
                destroy_mode=destroy_mode,
                name_suffix=f"shared-vm-cache-to-rsv-{region}",
            )

            # 2 & 4: VM → CACHE
            self._apply_or_remove_rule(
                rule_group="asr-shared-vm-to-cache",
                current=ctx,
                other=None,
                priority=ASR_SHARED_PRIORITY,
                ports=HTTPS_PORTS,
                sources=self._merge([vm_cidr]),
                destination_ips=cache_ips,
                destroy_mode=destroy_mode,
                name_suffix=f"shared-vm-to-cache-{region}",
            )

    # ----------------------------
    # Discovery
    # ----------------------------
    def _discover_region_context(self, regions: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        For each region, discover:
          - vm_subnet      (the app's VM subnet)
          - vm_nsg_info    (NSG on the VM subnet)
          - rsv_pe_ips     (list[str] private IPs on RSV PE NICs in that region)
          - cache_pe_ips   (list[str] private IPs on Cache Storage Account PEs in that region)
        """
        result: Dict[str, Dict[str, Any]] = {}

        for region in regions:
            vnet_name, vnet_rg = self.azure_resource_manager.get_vnet_and_rg_for_region(region)
            if not vnet_name or not vnet_rg:
                logging.warning("Missing VNet mapping for region; skipping region in ASR discovery.",
                                extra={"region": region})
                continue

            # 1) Find the application VM subnet (exclude PE subnets)
            vm_subnet = None
            nsg_info: Optional[NsgInfo] = None

            for subnet in self.azure_service.network_client.subnets.list(vnet_rg, vnet_name):
                name = getattr(subnet, "name", "") or ""
                # Heuristic: must include application name, and NOT be a PE subnet name
                if self.manager.application_name.lower() in name.lower() and "pe" not in name.lower():
                    vm_subnet = subnet
                    nsg_info = self._extract_nsg_info(subnet)
                    break

            # 2) Collect PE IPs in the same resource group (RSV + Cache)
            rsv_ips: List[str] = []
            cache_ips: List[str] = []
            try:
                for pe in self.azure_service.network_client.private_endpoints.list(vnet_rg):
                    pe_name = (getattr(pe, "name", "") or "").lower()
                    # classify by name – adjust if your naming differs
                    if "rsv" in pe_name or "recovery" in pe_name:
                        rsv_ips.extend(self._extract_pe_private_ips(pe))
                    if "cache" in pe_name or "storage" in pe_name:
                        cache_ips.extend(self._extract_pe_private_ips(pe))
            except Exception as e:
                logging.warning("Unable to enumerate Private Endpoints; skipping PE IP discovery for region.",
                                extra={"region": region, "error": str(e)})

            result[region] = {
                "vm_subnet": vm_subnet,
                "vm_nsg_info": nsg_info,
                "rsv_pe_ips": sorted(set([ip for ip in rsv_ips if ip])),
                "cache_pe_ips": sorted(set([ip for ip in cache_ips if ip])),
            }

        return result

    # ----------------------------
    # Rule application
    # ----------------------------
    def _apply_or_remove_rule(
        self,
        rule_group: str,
        current: Optional[Dict[str, Any]],
        other: Optional[Dict[str, Any]],
        priority: int,
        ports: List[str],
        sources: List[Optional[str]],
        destination_cidr: Optional[str] = None,
        destination_ips: Optional[List[str]] = None,
        destroy_mode: bool = False,
        name_suffix: str = "",
    ) -> None:
        """
        Creates/updates/removes a single logical rule set on the current region's **VM subnet NSG**.
        - Sources: list of CIDR strings or IP strings (None entries ignored)
        - Destination: either a single CIDR or a list of IPs (one rule per destination IP)
        """
        if not current or not current.get("vm_subnet"):
            return

        nsg_info = current.get("vm_nsg_info")
        if not nsg_info or not nsg_info.nsg_id:
            logging.warning("No NSG on VM subnet; skipping ASR rule.",
                            extra={"rule_group": rule_group, "name_suffix": name_suffix})
            return

        # Clean inputs
        srcs = [s for s in sources if s]
        if not srcs:
            logging.warning("No valid sources for ASR rule; skipping.",
                            extra={"rule_group": rule_group, "name_suffix": name_suffix})
            return

        # Destination fan-out: if destination_ips provided, create one rule per IP.
        destinations: List[str] = []
        dest_mode = "cidr"
        if destination_ips:
            destinations = [ip for ip in destination_ips if ip]
            dest_mode = "ip"
        elif destination_cidr:
            destinations = [destination_cidr]
            dest_mode = "cidr"
        else:
            logging.warning("No valid destination for ASR rule; skipping.",
                            extra={"rule_group": rule_group, "name_suffix": name_suffix})
            return

        for dest in destinations:
            rule_obj = PlatformAllowRule(
                source_address_prefixes=srcs,
                destination_address_prefixes=[dest],
                application_name=self.manager.application_name,
                resource_name=f"asr-{name_suffix}",
                nsg_name=nsg_info.nsg_name,
                vnet_rg=nsg_info.vnet_rg,
                subnet_cidr=self._cidr_or_none(current.get("vm_subnet")),
                ports=ports,
                priority=priority,
            )

            if destroy_mode:
                logging.info("Removing ASR NSG rule.",
                             extra={"group": rule_group, "name": rule_obj.name, "dest_mode": dest_mode})
                self.operations.remove_rule(rule_obj)
            else:
                logging.info("Creating/Updating ASR NSG rule.",
                             extra={"group": rule_group, "name": rule_obj.name, "dest_mode": dest_mode})
                self.operations.create_or_update_rule(rule_obj)

    # ----------------------------
    # Helpers
    # ----------------------------
    def _merge(self, lists: List[List[Optional[str]]]) -> List[Optional[str]]:
        merged: List[Optional[str]] = []
        for li in lists:
            if not li:
                continue
            merged.extend(li)
        return merged

    def _extract_nsg_info(self, subnet: Any) -> NsgInfo:
        nsg_id = getattr(getattr(subnet, "network_security_group", None), "id", None)
        if not nsg_id:
            return NsgInfo(None, None, None)
        # Parse resource group and NSG name from the ID
        parts = nsg_id.split("/")
        try:
            rg = parts[parts.index("resourceGroups") + 1]
            nsg_name = parts[parts.index("networkSecurityGroups") + 1]
        except ValueError:
            rg, nsg_name = (None, None)
        return NsgInfo(nsg_id, nsg_name, rg)

    def _cidr_or_none(self, subnet: Any) -> Optional[str]:
        if not subnet:
            return None
        if hasattr(subnet, "address_prefix") and subnet.address_prefix:
            return subnet.address_prefix
        if hasattr(subnet, "address_prefixes") and subnet.address_prefixes:
            return subnet.address_prefixes[0]
        return None

    def _extract_pe_private_ips(self, pe_obj: Any) -> List[str]:
        """
        Returns all allocated private IPs for a Private Endpoint (across NIC configs).
        """
        ips: List[str] = []
        # Private Endpoint -> network_interfaces -> ip_configurations -> private_ip_address
        try:
            for nic in getattr(pe_obj, "network_interfaces", []) or []:
                for ipconf in getattr(nic, "ip_configurations", []) or []:
                    ip = getattr(ipconf, "private_ip_address", None)
                    if ip:
                        ips.append(ip)
        except Exception:
            pass
        # Some SDK shapes are different; also try the direct property if present.
        if not ips:
            try:
                for ipconf in getattr(pe_obj, "ip_configurations", []) or []:
                    ip = getattr(ipconf, "private_ip_address", None)
                    if ip:
                        ips.append(ip)
            except Exception:
                pass
        return ips









Main.py 

# NEW import near the top with others
from asr_nsg_handler import AsrNsgRulesHandler

# after you build: manager, azure_service, subnet_manager, operations, azure_resource_manager
akv_handler = AKVNSGAllowRulesForAppSubnets(
    manager, operations, subnet_manager, azure_service, azure_resource_manager
)

subnet_to_subnet_handler = SubnetToSubnetNSGAllowRulesHandler(
    manager, operations, subnet_manager, azure_service, azure_resource_manager
)

# NEW: ASR handler
asr_handler = AsrNsgRulesHandler(
    manager, operations, subnet_manager, azure_service, azure_resource_manager
)

# Execute (order: AKV → S2S → ASR is fine; swap if you prefer)
akv_handler.process_rules(destroy_mode)
subnet_to_subnet_handler.process_rules(destroy_mode)
asr_handler.process_rules(destroy_mode)

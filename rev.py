# asr_nsg_rules.py

from typing import Dict, List, Optional
import logging
from dataclasses import dataclass

from nsg_rules import PlatformAllowRule, NsgRuleOperations
from azure_services import AzureNetworkService, AzureResourceManager, NsgManager

PORTS_HTTPS = ["443"]
ASR_RULE_PRIORITY = 450  # pick a stable, unused priority (adjust if needed)

@dataclass
class NsgInfo:
    id: Optional[str]
    name: Optional[str]
    vnet_rg: Optional[str]

class ASRNSGRulesHandler:
    """
    Create/remove ASR NSG Allow rules between two specific subnets (CUS <-> EUS2).
    - Condition 1: src = EUS2 subnet + CUS RSV PE IPs -> dst = CUS subnet (443)
    - Condition 2: src = CUS subnet + EUS2 RSV PE IPs -> dst = EUS2 subnet (443)
    """

    def __init__(
        self,
        manager: NsgManager,
        operations: NsgRuleOperations,
        azure_service: AzureNetworkService,
        azure_resource_manager: AzureResourceManager,
        cus_subnet_name: str,
        eus2_subnet_name: str,
        rsv_pe_ips_by_region: Dict[str, List[str]],  # {"cus": ["10.0.1.5"], "eus2": ["10.1.2.7", ...]}
    ):
        self.manager = manager
        self.operations = operations
        self.azure = azure_service
        self.arm = azure_resource_manager
        self.cus_subnet_name = cus_subnet_name
        self.eus2_subnet_name = eus2_subnet_name
        self.rsv_pe_ips_by_region = rsv_pe_ips_by_region

    # ---------------------- Public API ----------------------

    def apply(self, destroy: bool = False) -> None:
        """
        Apply or remove both ASR rules.
        """
        cus = self._get_subnet(region="cus", subnet_name=self.cus_subnet_name)
        eus2 = self._get_subnet(region="eus2", subnet_name=self.eus2_subnet_name)

        if not cus or not eus2:
            raise RuntimeError("Could not resolve both subnets. Check names/VNet mappings.")

        cus_cidr = self._get_subnet_cidr(cus)
        eus2_cidr = self._get_subnet_cidr(eus2)
        cus_nsg = self._get_nsg_info(cus)
        eus2_nsg = self._get_nsg_info(eus2)

        if not all([cus_cidr, eus2_cidr, cus_nsg.id, eus2_nsg.id]):
            raise RuntimeError("Missing NSG or CIDR on one of the subnets.")

        # Condition 1: Create rule ON CUS NSG (dest=CUS)
        src_prefixes_cus_rule = [eus2_cidr] + self.rsv_pe_ips_by_region.get("cus", [])
        self._upsert_or_remove_rule(
            nsg=eus2_nsg if False else cus_nsg,  # make it obvious we target CUS NSG here
            dest_cidr=cus_cidr,
            src_prefixes=src_prefixes_cus_rule,
            rule_tag="asr-cus",
            destroy=destroy,
        )

        # Condition 2: Create rule ON EUS2 NSG (dest=EUS2)
        src_prefixes_eus2_rule = [cus_cidr] + self.rsv_pe_ips_by_region.get("eus2", [])
        self._upsert_or_remove_rule(
            nsg=eus2_nsg,
            dest_cidr=eus2_cidr,
            src_prefixes=src_prefixes_eus2_rule,
            rule_tag="asr-eus2",
            destroy=destroy,
        )

        logging.info("ASR NSG rules processed.", extra={"destroy_mode": destroy})

    # ---------------------- Internals ----------------------

    def _upsert_or_remove_rule(
        self,
        nsg: "NsgInfo",
        dest_cidr: str,
        src_prefixes: List[str],
        rule_tag: str,
        destroy: bool,
    ):
        """
        Create/Update or Remove a single NSG rule.
        """
        rule = PlatformAllowRule(
            source_address_prefixes=src_prefixes,
            destination_address_prefixes=[dest_cidr],
            application_name=self.manager.application_name,
            resource_name=rule_tag,  # becomes part of the rule name
            nsg_name=nsg.name,
            vnet_rg=nsg.vnet_rg,
            subnet_cidr=dest_cidr,
            ports=PORTS_HTTPS,
            priority=ASR_RULE_PRIORITY,
        )

        if destroy:
            logging.info("Removing ASR NSG rule.", extra={"rule": rule.name, "nsg": nsg.name})
            self.operations.remove_rule(rule)
        else:
            logging.info(
                "Creating/Updating ASR NSG rule.",
                extra={
                    "rule": rule.name,
                    "nsg": nsg.name,
                    "src_prefixes": src_prefixes,
                    "dest_cidr": dest_cidr,
                    "ports": PORTS_HTTPS,
                    "priority": ASR_RULE_PRIORITY,
                },
            )
            self.operations.create_or_update_rule(rule)

    def _get_subnet(self, region: str, subnet_name: str):
        """
        Resolve a subnet object by (region, subnet_name) using your AzureResourceManager
        to find the VNet/RG, then list subnets in that VNet and match by name.
        """
        vnet_name, vnet_rg = self.arm.get_vnet_and_rg_for_region(region)
        if not vnet_name or not vnet_rg:
            raise RuntimeError(f"Missing VNet mapping for region '{region}'.")
        for s in self.azure.network_client.subnets.list(vnet_rg, vnet_name):
            if getattr(s, "name", "").lower() == subnet_name.lower():
                return s
        raise RuntimeError(f"Subnet '{subnet_name}' not found in {region} / {vnet_rg}/{vnet_name}")

    def _get_subnet_cidr(self, subnet) -> Optional[str]:
        if hasattr(subnet, "address_prefix") and subnet.address_prefix:
            return subnet.address_prefix
        if hasattr(subnet, "address_prefixes") and subnet.address_prefixes:
            return subnet.address_prefixes[0]
        return None

    def _get_nsg_info(self, subnet) -> NsgInfo:
        """
        Pull NSG id/name/rg from the subnet's attached NSG.
        """
        nsg_id = getattr(getattr(subnet, "network_security_group", None), "id", None)
        if not nsg_id:
            return NsgInfo(None, None, None)

        # Parse: .../resourceGroups/<RG>/providers/Microsoft.Network/networkSecurityGroups/<NSG>
        try:
            parts = nsg_id.split("/")
            rg = parts[parts.index("resourceGroups") + 1]
            name = parts[-1]
            return NsgInfo(nsg_id, name, rg)
        except Exception:
            logging.warning("Failed to parse NSG id.", extra={"nsg_id": nsg_id})
            return NsgInfo(nsg_id, None, None)

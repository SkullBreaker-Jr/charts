# requirements:
#   pip install azure-identity azure-mgmt-network
from dataclasses import dataclass
from typing import List, Optional, Dict
import re
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import SecurityRule, SecurityRuleProtocol

# ------------ Config & Types ------------

@dataclass
class AsrRuleSpec:
    # Rule identity
    name: str
    priority: int
    # NSG where the rule will be created/updated
    nsg_rg: str
    nsg_name: str
    # Source (subnet CIDR)
    source_subnet_rg: str
    source_vnet: str
    source_subnet: str
    # Destination (Private Endpoint)
    pe_rg: str
    pe_name: str
    # Optional tags for traceability
    app: Optional[str] = None
    region: Optional[str] = None

# ------------ Helpers ------------

def get_subnet_cidr(net: NetworkManagementClient, rg: str, vnet: str, subnet: str) -> str:
    sn = net.subnets.get(rg, vnet, subnet)
    # Prefer first address_prefix (supports list-or-str shapes)
    if isinstance(sn.address_prefixes, list) and sn.address_prefixes:
        return sn.address_prefixes[0]
    return sn.address_prefix

def get_private_endpoint_ips(net: NetworkManagementClient, rg: str, pe_name: str) -> List[str]:
    """Return all NIC private IPs assigned to the Private Endpoint."""
    pe = net.private_endpoints.get(rg, pe_name)
    ips: List[str] = []
    # Each PE holds one or more NICs
    for nic_ref in (pe.network_interfaces or []):
        # nic_ref.id looks like: /subscriptions/.../resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nicName
        nic_id = nic_ref.id.split("/networkInterfaces/")[-1]
        nic_rg = re.search(r"/resourceGroups/([^/]+)/", nic_ref.id).group(1)
        nic = net.network_interfaces.get(nic_rg, nic_id)
        for ipconf in nic.ip_configurations or []:
            if ipconf.private_ip_address:
                ips.append(ipconf.private_ip_address)
    # Deduplicate and keep order
    seen = set(); uniq = []
    for ip in ips:
        if ip not in seen:
            uniq.append(ip); seen.add(ip)
    return uniq

def ensure_https_allow_rule(
    net: NetworkManagementClient,
    spec: AsrRuleSpec,
    source_cidr: str,
    dest_ips: List[str],
):
    """Create/Update an inbound HTTPS rule on the destination NSG, allowing from source_cidr to dest_ips."""
    # Fetch existing NSG (ensures it exists)
    nsg = net.network_security_groups.get(spec.nsg_rg, spec.nsg_name)

    rule = SecurityRule(
        name=spec.name,
        access="Allow",
        direction="Inbound",
        description=f"ASR allow 443 from {spec.source_vnet}/{spec.source_subnet} ({source_cidr}) "
                    f"to PE {spec.pe_rg}/{spec.pe_name} (IPs: {', '.join(dest_ips)})"
                    + (f" | app={spec.app}" if spec.app else "")
                    + (f" | region={spec.region}" if spec.region else ""),
        priority=spec.priority,
        protocol=SecurityRuleProtocol.tcp,
        source_port_range="*",
        destination_port_range="443",
        source_address_prefix=source_cidr,
        destination_address_prefixes=dest_ips or ["0.0.0.0"],  # must be non-empty; fail-safe
    )

    # Upsert (idempotent)
    poller = net.security_rules.begin_create_or_update(
        resource_group_name=spec.nsg_rg,
        network_security_group_name=spec.nsg_name,
        security_rule_name=spec.name,
        security_rule_parameters=rule,
    )
    return poller.result()

# ------------ Orchestrator ------------

def apply_asr_rules(
    subscription_id: str,
    specs: List[AsrRuleSpec],
):
    cred = DefaultAzureCredential()
    net = NetworkManagementClient(credential=cred, subscription_id=subscription_id)

    results: Dict[str, str] = {}
    for s in specs:
        src_cidr = get_subnet_cidr(net, s.source_subnet_rg, s.source_vnet, s.source_subnet)
        pe_ips = get_private_endpoint_ips(net, s.pe_rg, s.pe_name)
        if not pe_ips:
            raise RuntimeError(f"No IPs found for Private Endpoint {s.pe_rg}/{s.pe_name}")
        res = ensure_https_allow_rule(net, s, src_cidr, pe_ips)
        results[s.name] = f"applied (priority {s.priority}) to {s.nsg_rg}/{s.nsg_name}"
    return results

# ------------ Example usage ------------

if __name__ == "__main__":
    SUBSCRIPTION_ID = "<your-subscription-id>"

    # Example priorities—keep them below other platform rules, e.g., 510–519 reserved for ASR
    specs = [
        # Dedicated: CUS subnet -> CUS RSV PE
        AsrRuleSpec(
            name="ASR-ALLOW-HTTPS-CUS-to-CUS-RSV",
            priority=510,
            nsg_rg="rg-cus-network",
            nsg_name="nsg-cus-rsv-subnet",     # NSG attached to RSV PE's subnet (destination side)
            source_subnet_rg="rg-cus-app",
            source_vnet="vnet-cus-app",
            source_subnet="snet-cus-app",
            pe_rg="rg-cus-rsv",
            pe_name="pe-cus-rsv",
            app="myApp",
            region="cus"
        ),
        # Dedicated (failover): EUS2 subnet -> EUS2 RSV PE
        AsrRuleSpec(
            name="ASR-ALLOW-HTTPS-EUS2-to-EUS2-RSV",
            priority=511,
            nsg_rg="rg-eus2-network",
            nsg_name="nsg-eus2-rsv-subnet",
            source_subnet_rg="rg-eus2-app",
            source_vnet="vnet-eus2-app",
            source_subnet="snet-eus2-app",
            pe_rg="rg-eus2-rsv",
            pe_name="pe-eus2-rsv",
            app="myApp",
            region="eus2"
        ),

        # Shared: CUS VM subnet -> CUS Cache SA PE
        AsrRuleSpec(
            name="ASR-ALLOW-HTTPS-CUS-VM-to-CUS-CachePE",
            priority=512,
            nsg_rg="rg-cus-network",
            nsg_name="nsg-cus-cache-subnet",
            source_subnet_rg="rg-cus-app",
            source_vnet="vnet-cus-app",
            source_subnet="snet-cus-vm",
            pe_rg="rg-cus-storage",
            pe_name="pe-cus-cache",
            app="centralus-cache",
            region="cus"
        ),

        # Shared: EUS2 VM subnet -> EUS2 Cache SA PE
        AsrRuleSpec(
            name="ASR-ALLOW-HTTPS-EUS2-VM-to-EUS2-CachePE",
            priority=513,
            nsg_rg="rg-eus2-network",
            nsg_name="nsg-eus2-cache-subnet",
            source_subnet_rg="rg-eus2-app",
            source_vnet="vnet-eus2-app",
            source_subnet="snet-eus2-vm",
            pe_rg="rg-eus2-storage",
            pe_name="pe-eus2-cache",
            app="eastus2-cache",
            region="eus2"
        ),
    ]

    print(apply_asr_rules(SUBSCRIPTION_ID, specs))

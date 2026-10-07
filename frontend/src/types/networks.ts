/** Defined.net-style inbound rule: who can send traffic to this group. */
export interface InboundFirewallRule {
  allowed_group: string;
  protocol: "any" | "tcp" | "udp" | "icmp" | "icmpv6";
  port_range: string;
  description?: string;
}

export interface Network {
  id: number;
  name: string;
  subnet_cidr: string;
  /** CIDRs embedded in every host cert for mesh L3 (default fd00::/8). */
  cert_subnets: string[];
  ca_cert_path: string | null;
  cert_version: number;
  cert_curve: "25519" | "P256";
  created_at: string;
  role?: string;
  can_manage_nodes?: boolean;
  can_invite_users?: boolean;
  can_manage_firewall?: boolean;
  /** Summary counts for the card grid. Node active/total isn't here - it's computed
   * client-side from the node list (see utils/nodeStatus.ts). */
  group_count: number;
  dns_entry_count: number;
  user_count: number;
}

export interface NetworkCreate {
  name: string;
  subnet_cidr: string;
  cert_curve?: "25519" | "P256";
  /** Omit to use default expansive ULA claim fd00::/8 on every host cert. */
  cert_subnets?: string[];
}

export interface NetworkUpdateData {
  // No network-level firewall; use Groups page for per-group inbound rules.
  cert_subnets?: string[];
}

export interface GroupFirewallConfig {
  group_name: string;
  inbound_rules: InboundFirewallRule[];
}

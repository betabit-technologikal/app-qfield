import { useCallback, useEffect, useState } from "react";
import { Card, Button, TextInput, Label, Select } from "flowbite-react";
import { HiPlus } from "react-icons/hi";
import { useNavigate } from "react-router-dom";
import type { Network, NetworkCreate } from "../types/networks";
import type { Node } from "../types/nodes";
import { listNetworks, listNodes, createNetwork } from "../api/client";
import { isNodeActive } from "../utils/nodeStatus";
import { useErrorToast } from "../contexts/ToastContext";

/** Random ULA /64 for opinionated IPv6-first network create (fd + 40-bit id + 16-bit subnet). */
function randomUla64(): string {
  const bytes = new Uint8Array(7);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  // fd + 40 bits (10 hex) + 16 bits (4 hex) → /64
  const g = hex.slice(0, 10);
  const s = hex.slice(10, 14);
  return `fd${g.slice(0, 2)}:${g.slice(2, 6)}:${g.slice(6, 10)}:${s}::/64`;
}

function blankNetworkForm(): NetworkCreate {
  return {
    name: "",
    subnet_cidr: randomUla64(),
    cert_curve: "25519",
    cert_subnets: ["fd00::/8"],
  };
}

export function Networks() {
  const navigate = useNavigate();
  const [networks, setNetworks] = useState<Network[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [loading, setLoading] = useState(true);
  const setError = useErrorToast();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<NetworkCreate>(blankNetworkForm);
  const load = useCallback(() => {
    setLoading(true);
    Promise.all([listNetworks(), listNodes()])
      .then(([n, nd]) => {
        setNetworks(n);
        setNodes(nd);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [setError]);

  useEffect(() => {
    const id = setTimeout(load, 0);
    return () => clearTimeout(id);
  }, [load]);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cert_subnets = (form.cert_subnets ?? [])
      .map((s) => s.trim())
      .filter(Boolean);
    const payload: NetworkCreate = {
      ...form,
      cert_subnets: cert_subnets.length ? cert_subnets : ["fd00::/8"],
    };
    console.info("[networks] create_network request", payload);
    createNetwork(payload)
      .then((created) => {
        console.info("[networks] create_network ok", created);
        setForm(blankNetworkForm());
        setShowForm(false);
        load();
      })
      .catch((err) => {
        console.error("[networks] create_network failed", {
          ...payload,
          error: err?.message ?? err,
        });
        setError(err.message);
      });
  };

  const nodeCounts = (networkId: number): { active: number; total: number } => {
    const inNetwork = nodes.filter((n) => n.network_id === networkId);
    return { active: inNetwork.filter(isNodeActive).length, total: inNetwork.length };
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Networks</h1>
        <Button
          onClick={() => setShowForm(!showForm)}
          color={showForm ? "gray" : "purple"}
          data-onboarding-target="networks-create-button"
        >
          <HiPlus className="mr-2 h-5 w-5" />
          {showForm ? "Cancel" : "Add Network"}
        </Button>
      </div>

      {showForm && (
        <Card className="mb-6">
          <h2 className="text-xl font-semibold mb-4">Create Network</h2>
          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <Label htmlFor="name" value="Network Name" />
              <TextInput
                id="name"
                type="text"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="my-network"
                required
              />
            </div>
            <div>
              <Label htmlFor="subnet" value="Allocation CIDR (IPv6 overlay)" />
              <TextInput
                id="subnet"
                type="text"
                value={form.subnet_cidr}
                onChange={(e) => setForm((f) => ({ ...f, subnet_cidr: e.target.value }))}
                placeholder="fd00:abcd:ef01:2345::/64"
                required
              />
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                IPv6 prefix used to assign each node a tunnel address. Default is a random ULA /64.
                Allowed prefix lengths: /8 through /96 (nothing tighter than /96).
              </p>
            </div>
            <div>
              <Label htmlFor="cert_subnets" value="Cert subnets (mesh L3 claims)" />
              <TextInput
                id="cert_subnets"
                type="text"
                value={(form.cert_subnets ?? []).join(", ")}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    cert_subnets: e.target.value
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                  }))
                }
                placeholder="fd00::/8"
              />
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Comma-separated CIDRs baked into every host certificate so peers share VPN
                networks beyond the allocation pool. Default expansive ULA is{" "}
                <code className="text-xs">fd00::/8</code>. Security is host/Nebula firewall +
                FRR, not narrow cert prefixes.
              </p>
            </div>
            <div>
              <Label htmlFor="cert_curve" value="Certificate Curve" />
              <Select
                id="cert_curve"
                value={form.cert_curve}
                onChange={(e) =>
                  setForm((f) => ({ ...f, cert_curve: e.target.value as "25519" | "P256" }))
                }
              >
                <option value="25519">Curve25519 (default)</option>
                <option value="P256">P256</option>
              </Select>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Applies to every node on this network. Cannot be changed after creation.
              </p>
            </div>
            <Button type="submit" color="purple">
              Create Network
            </Button>
          </form>
        </Card>
      )}

      {loading ? (
        <Card>
          <p className="text-gray-600 dark:text-gray-400">Loading networks...</p>
        </Card>
      ) : (
        <Card>
          {networks.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-gray-500 dark:text-gray-400 mb-2">No networks yet.</p>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                Create an IPv6 overlay network (ULA allocation CIDR). Configure per-group firewall rules on the Groups page.
              </p>
              <Button color="purple" onClick={() => setShowForm(true)} data-onboarding-target="networks-create-button">
                <HiPlus className="mr-2 h-5 w-5" />
                Add your first network
              </Button>
            </div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
              {networks.map((n) => {
                const { active, total } = nodeCounts(n.id);
                return (
                  <button
                    key={n.id}
                    type="button"
                    onClick={() => navigate(`/networks/${n.id}`)}
                    className="relative aspect-square rounded-lg border border-gray-200 dark:border-gray-700 bg-[var(--nc-bg2-light)] dark:bg-[var(--nc-bg2-dark)] p-4 text-left shadow-sm hover:shadow-md transition-shadow flex flex-col"
                  >
                    <p className="font-semibold text-lg text-[var(--nc-bg2-light-contrast)] dark:text-[var(--nc-bg2-dark-contrast)] truncate" title={n.name}>
                      {n.name}
                    </p>
                    <p className="text-xs font-mono text-gray-500 dark:text-gray-400 truncate mb-3">
                      {n.subnet_cidr}
                    </p>
                    <div className="mt-auto grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Nodes</div>
                        <div className="font-semibold text-[var(--nc-bg2-light-contrast)] dark:text-[var(--nc-bg2-dark-contrast)]">
                          {active}/{total}
                        </div>
                      </div>
                      <div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Groups</div>
                        <div className="font-semibold text-[var(--nc-bg2-light-contrast)] dark:text-[var(--nc-bg2-dark-contrast)]">{n.group_count}</div>
                      </div>
                      <div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">DNS Entries</div>
                        <div className="font-semibold text-[var(--nc-bg2-light-contrast)] dark:text-[var(--nc-bg2-dark-contrast)]">{n.dns_entry_count}</div>
                      </div>
                      <div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">Users</div>
                        <div className="font-semibold text-[var(--nc-bg2-light-contrast)] dark:text-[var(--nc-bg2-dark-contrast)]">{n.user_count}</div>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

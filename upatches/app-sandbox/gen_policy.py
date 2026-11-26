#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Generate sandbox_policy of app-sandbox as a raw BTF variable value.

The rules of each sandbox come from the input, the policy bit of each
from the [[upatches.policy]] table of the Beefile that has its name.
"""

import argparse
import ipaddress
from pathlib import Path
import struct
import tomllib

SANDBOX_MAX = 32
CGROUP_MAX = 32
NET_MAX = 128
PORT_MAX = 64
FIM_MAX = 64
GLOB_MAX = 32

FIM_OPS = {"create": 0x1, "rename": 0x2, "write": 0x4, "read": 0x8}
FIM_UNIX = 0x10
FIM_UNIX_PATH = 0x20
DENY_KEYS = set(FIM_OPS) | {"network", "ports", "unix"}
SANDBOX_KEYS = {
	"exec",
	"families",
	"network",
	"ports",
	"cgroup_ids",
	"deny_ptrace",
	"deny",
}
FAMILIES = {
	"unix": 1,
	"inet": 2,
	"inet6": 10,
	"netlink": 16,
	"vsock": 40,
}
PROTO_BITS = {
	"tcp": 0x1,
	"udp": 0x2,
}
MAPPED_V4 = ipaddress.ip_network("::ffff:0:0/96")


def strings(value, where):
	if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
		raise ValueError(f"{where}: expected an array of strings")
	return value


def policy_bits(beefile):
	"""The bit of every policy ID the Beefile declares."""
	with beefile.open("rb") as stream:
		upatches = tomllib.load(stream).get("upatches", [])
	bits = {}
	for upatch in upatches:
		for policy in upatch.get("policy", []):
			name, bit = policy.get("id"), policy.get("bit")
			# shirudo reads a bit as hexadecimal, TOML reads it as
			# decimal without 0x: only a one-hot value is the same bit
			# to both.
			if (not isinstance(bit, int) or isinstance(bit, bool) or
			    bit <= 0 or bit & (bit - 1) or bit >> 64):
				raise ValueError(f"{beefile}: policy {name}: write the bit as "
						 "one-hot hexadecimal with 0x")
			if bits.setdefault(name, bit) != bit:
				raise ValueError(f"{beefile}: policy {name} has two bits")
	return bits


def network_rule(text, where):
	try:
		network = ipaddress.ip_network(text, strict=False)
	except ValueError as error:
		raise ValueError(f"{where}: {error}") from error
	if network.version == 4:
		address = int(MAPPED_V4.network_address) | int(network.network_address)
		network = ipaddress.ip_network((address, 96 + network.prefixlen))
	return network.network_address.packed, network.netmask.packed


def networks(names, sets, where):
	rules = []
	for name in strings(names, where):
		if name.startswith("@"):
			if name[1:] not in sets:
				raise ValueError(f"{where}: no [networks] entry {name[1:]}")
			members = strings(sets[name[1:]], f"networks.{name[1:]}")
		else:
			members = [name]
		rules.extend(network_rule(member, where) for member in members)
	return rules


def family_mask(names, where):
	mask = 0
	for name in strings(names, where):
		if name not in FAMILIES:
			raise ValueError(f"{where}: unknown socket family {name!r}")
		mask |= 1 << FAMILIES[name]
	return mask


def cgroup_id_list(values, where):
	if not isinstance(values, list) or not values:
		raise ValueError(f"{where}: expected a non-empty array of positive cgroup IDs")
	out = []
	for item in values:
		if not isinstance(item, int) or isinstance(item, bool) or item <= 0 or item >> 64:
			raise ValueError(f"{where}: invalid cgroup ID {item!r}")
		out.append(item)
	return out


def parse_port_num(text, where):
	if not text.isdigit():
		raise ValueError(f"{where}: invalid port {text!r}")
	port = int(text)
	if port < 1 or port > 65535:
		raise ValueError(f"{where}: port {port} out of range 1..65535")
	return port


def port_rules(values, where):
	if not isinstance(values, list):
		raise ValueError(f"{where}: expected an array of ports")
	rules = []
	for item in values:
		if isinstance(item, int) and not isinstance(item, bool):
			if item < 1 or item > 65535:
				raise ValueError(f"{where}: port {item} out of range 1..65535")
			rules.append((item, item, 0x3))
			continue
		if not isinstance(item, str) or not item:
			raise ValueError(f"{where}: invalid port entry {item!r}")
		protos = 0x3
		spec = item
		if "/" in item:
			proto_name, _, spec = item.partition("/")
			if proto_name not in PROTO_BITS:
				raise ValueError(f"{where}: unknown port protocol {proto_name!r}")
			protos = PROTO_BITS[proto_name]
		if "-" in spec:
			lo_str, _, hi_str = spec.partition("-")
			start = parse_port_num(lo_str, where)
			end = parse_port_num(hi_str, where)
			if start > end:
				raise ValueError(f"{where}: port range {item!r} has start > end")
		else:
			start = end = parse_port_num(spec, where)
		rules.append((start, end, protos))
	return rules


def glob_rule(pattern, where, allow_slash=False):
	raw = pattern.encode()
	if not raw or b"\0" in raw or (not allow_slash and b"/" in raw):
		raise ValueError(f"{where}: {pattern!r} is not a valid pattern")
	if raw.startswith(b"*") and raw.endswith(b"*") and len(raw) >= 3 and b"*" not in raw[1:-1]:
		needle = raw[1:-1]
		if len(needle) > GLOB_MAX:
			raise ValueError(f"{where}: {pattern!r} has more than {GLOB_MAX} bytes")
		return needle, b"", 2
	if raw.count(b"*") > 1:
		raise ValueError(f"{where}: {pattern!r} has unsupported '*' placement")
	prefix, star, suffix = raw.partition(b"*")
	if len(prefix) > GLOB_MAX or len(suffix) > GLOB_MAX:
		raise ValueError(f"{where}: {pattern!r} has more than {GLOB_MAX} "
				 "bytes on one side of its '*'")
	return prefix, suffix, 1 if star else 0


def add_net_rule(table_dict, key, allow_bit, deny_bit):
	allow_sb, deny_sb = table_dict.get(key, (0, 0))
	table_dict[key] = (allow_sb | allow_bit, deny_sb | deny_bit)


def add_fim_rule(table_dict, key, bit, op_bit):
	sandboxes, ops = table_dict.get(key, (0, 0))
	table_dict[key] = (sandboxes | bit, ops | op_bit)


def read_policy(path, bits):
	with path.open("rb") as stream:
		config = tomllib.load(stream)
	unknown = set(config) - {"networks", "sandbox"}
	if unknown:
		raise ValueError(f"{path}: unknown table {sorted(unknown)[0]}")
	sets = config.get("networks", {})
	if not isinstance(sets, dict):
		raise ValueError(f"{path}: [networks] must be a table")
	sandboxes_cfg = config.get("sandbox", {})
	if not isinstance(sandboxes_cfg, dict):
		raise ValueError(f"{path}: [sandbox] must be a table")
	policy = {
		"sandboxes": 0,
		"cgroup_scoped": 0,
		"exec_enforced": 0,
		"families_enforced": 0,
		"net_enforced": 0,
		"net_deny_enforced": 0,
		"port_enforced": 0,
		"port_deny_enforced": 0,
		"read_enforced": 0,
		"unix_enforced": 0,
		"ptrace_denied": 0,
		"exec": [],
		"families": [],
		"cgroup_ids": {},
		"net": {},
		"ports": {},
		"fim": {},
	}
	for name, sandbox in sandboxes_cfg.items():
		where = f"{path}: sandbox.{name}"
		if name not in bits:
			raise ValueError(f"{where}: the Beefile has no policy {name}")
		if not isinstance(sandbox, dict):
			raise ValueError(f"{where}: expected a table")
		unknown = set(sandbox) - SANDBOX_KEYS
		if unknown:
			raise ValueError(f"{where}: unknown key {sorted(unknown)[0]}")
		bit = bits[name]
		policy["sandboxes"] |= bit
		if "cgroup_ids" in sandbox:
			policy["cgroup_scoped"] |= bit
			for cg_id in cgroup_id_list(sandbox["cgroup_ids"], f"{where}.cgroup_ids"):
				policy["cgroup_ids"][cg_id] = policy["cgroup_ids"].get(cg_id, 0) | bit
		if "exec" in sandbox:
			allowed = bit
			for other in strings(sandbox["exec"], f"{where}.exec"):
				if other not in bits:
					raise ValueError(f"{where}.exec: the Beefile has no "
							 f"policy {other}")
				allowed |= bits[other]
			policy["exec_enforced"] |= bit
			policy["exec"].append((bit, allowed))
		if "families" in sandbox:
			allowed_fams = family_mask(sandbox["families"], f"{where}.families")
			policy["families_enforced"] |= bit
			policy["families"].append((bit, allowed_fams))
		if "network" in sandbox:
			policy["net_enforced"] |= bit
			for rule in networks(sandbox["network"], sets, f"{where}.network"):
				add_net_rule(policy["net"], rule, bit, 0)
		if "ports" in sandbox:
			policy["port_enforced"] |= bit
			for rule in port_rules(sandbox["ports"], f"{where}.ports"):
				add_net_rule(policy["ports"], rule, bit, 0)
		if "deny_ptrace" in sandbox:
			val = sandbox["deny_ptrace"]
			if not isinstance(val, bool):
				raise ValueError(f"{where}.deny_ptrace: expected a boolean")
			if val:
				policy["ptrace_denied"] |= bit
		deny = sandbox.get("deny", {})
		if not isinstance(deny, dict):
			raise ValueError(f"{where}.deny: expected a table")
		unknown = set(deny) - DENY_KEYS
		if unknown:
			raise ValueError(f"{where}.deny: unknown key {sorted(unknown)[0]}")
		if "network" in deny:
			rules = networks(deny["network"], sets, f"{where}.deny.network")
			if rules:
				policy["net_deny_enforced"] |= bit
			for rule in rules:
				add_net_rule(policy["net"], rule, 0, bit)
		if "ports" in deny:
			rules = port_rules(deny["ports"], f"{where}.deny.ports")
			if rules:
				policy["port_deny_enforced"] |= bit
			for rule in rules:
				add_net_rule(policy["ports"], rule, 0, bit)
		if "unix" in deny:
			patterns = strings(deny["unix"], f"{where}.deny.unix")
			if patterns:
				policy["unix_enforced"] |= bit
			for pattern in patterns:
				rule = glob_rule(pattern, f"{where}.deny.unix", allow_slash=True)
				op_bit = FIM_UNIX_PATH if "/" in pattern else FIM_UNIX
				add_fim_rule(policy["fim"], rule, bit, op_bit)
		for op in FIM_OPS:
			if op not in deny:
				continue
			patterns = strings(deny[op], f"{where}.deny.{op}")
			if op == "read" and patterns:
				policy["read_enforced"] |= bit
			for pattern in patterns:
				rule = glob_rule(pattern, f"{where}.deny.{op}")
				add_fim_rule(policy["fim"], rule, bit, FIM_OPS[op])
	return policy


def table(entries, limit, size, what):
	if len(entries) > limit:
		raise ValueError(f"{len(entries)} {what}; the object holds {limit}")
	return b"".join(entries).ljust(limit * size, b"\0")


def encode(policy):
	"""struct sandbox_policy of app-sandbox.bpf.c, little-endian."""
	execs = [struct.pack("<QQ", bit, allowed) for bit, allowed in policy["exec"]]
	families = [struct.pack("<QQ", bit, allowed)
		    for bit, allowed in policy["families"]]
	cgroups = [struct.pack("<QQ", cg_id, sandboxes)
		   for cg_id, sandboxes in sorted(policy["cgroup_ids"].items())]
	nets = [struct.pack("<QQ16s16s", allow_sb, deny_sb, address, mask)
		for (address, mask), (allow_sb, deny_sb)
		in sorted(policy["net"].items())]
	ports = [struct.pack("<QQHHB3x", allow_sb, deny_sb, start, end, protos)
		 for (start, end, protos), (allow_sb, deny_sb)
		 in sorted(policy["ports"].items())]
	fims = [struct.pack(f"<QBBBB4x{GLOB_MAX}s{GLOB_MAX}s", sandboxes, ops,
			    len(prefix), len(suffix), wildcard, prefix, suffix)
		for (prefix, suffix, wildcard), (sandboxes, ops)
		in sorted(policy["fim"].items())]
	header = struct.pack(
		"<11Q6I",
		policy["sandboxes"],
		policy["cgroup_scoped"],
		policy["exec_enforced"],
		policy["families_enforced"],
		policy["net_enforced"],
		policy["net_deny_enforced"],
		policy["port_enforced"],
		policy["port_deny_enforced"],
		policy["read_enforced"],
		policy["unix_enforced"],
		policy["ptrace_denied"],
		len(execs),
		len(families),
		len(cgroups),
		len(nets),
		len(ports),
		len(fims),
	)
	return (header +
		table(execs, SANDBOX_MAX, 16, "sandboxes with exec rules") +
		table(families, SANDBOX_MAX, 16, "sandboxes with family rules") +
		table(cgroups, CGROUP_MAX, 16, "pod cgroup IDs") +
		table(nets, NET_MAX, 48, "networks") +
		table(ports, PORT_MAX, 24, "port rules") +
		table(fims, FIM_MAX, 80, "file and UNIX socket patterns"))


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--input", required=True, type=Path)
	parser.add_argument("--symbol", required=True)
	parser.add_argument("--output", required=True, type=Path)
	parser.add_argument("--beefile", type=Path, default=Path("Beefile"))
	args = parser.parse_args()
	try:
		if args.symbol != "sandbox_policy":
			raise ValueError(f"unsupported symbol: {args.symbol}")
		policy = read_policy(args.input, policy_bits(args.beefile))
		args.output.write_bytes(encode(policy))
	except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
		parser.error(str(error))
	return 0


if __name__ == "__main__":
	raise SystemExit(main())

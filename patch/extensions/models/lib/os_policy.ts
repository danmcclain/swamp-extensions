/**
 * The OS update policy of a machine: what @dmc/patch may do to the host's OS packages and
 * reboots, and what the host's own updater is allowed to install. Pure: no I/O, no swamp.
 *
 *   managed    @dmc/patch scans, upgrades (safeOsUpdate) and reboots the host.
 *   auto       the host installs its own OS updates (unattended upgrades and the like).
 *              @dmc/patch scans and reboots, but never upgrades. osAutoScope says what the
 *              host's updater installs: security updates only, or everything.
 *   scan-only  @dmc/patch only scans. It never upgrades and never reboots.
 *
 * `os: false` turns off OS collection and OS upgrades, not reboots: a reboot follows the
 * policy alone.
 *
 * The fleet sets a default policy (globalArguments) and a machine may override it. A
 * policy this module does not know is refused, and so is an osAutoScope that the effective
 * policy does not use: a configuration that is wrong is an error, never silently ignored.
 *
 * capabilitiesFor is the single source of truth for what a machine may do. The runtime
 * guards in patch_fleet.ts and the sudoers generator both read it.
 *
 * @module
 */
import { unsafeRecord } from "./access_policy.ts";
import type { UnsafeT } from "./access_policy.ts";

export const OS_UPDATE_POLICIES = ["managed", "auto", "scan-only"] as const;
export type OsUpdatePolicy = typeof OS_UPDATE_POLICIES[number];

export const OS_AUTO_SCOPES = ["security", "all"] as const;
export type OsAutoScope = typeof OS_AUTO_SCOPES[number];

/** The machine fields the policy reads: a structural subset of a fleet Machine. */
export interface PolicyMachine {
  /** Named in error messages only. */
  host?: string;
  /** false = OS collection and OS actions are off for this machine. Absent = true. */
  os?: boolean;
  osUpdatePolicy?: OsUpdatePolicy;
  osAutoScope?: OsAutoScope;
  /** Present = the machine has a docker block (an app layer, not an OS action). */
  docker?: unknown;
  /** Present = a plugged model scans and upgrades the OS, not the built-in collector. */
  osUpdater?: unknown;
  reach?: "ssh" | "pct";
  unsafe?: UnsafeT;
}

/** The fleet defaults the policy reads: a structural subset of the fleet GlobalArgs. */
export interface PolicyGlobals {
  osUpdatePolicy?: OsUpdatePolicy;
  osAutoScope?: OsAutoScope;
}

/** The policy a machine ends up with, and what its host's own updater installs. */
export interface EffectivePolicy {
  policy: OsUpdatePolicy;
  /** Non-null only when the policy is auto. */
  autoScope: OsAutoScope | null;
}

/** What @dmc/patch may do on one machine. */
export interface Capabilities {
  /** The read-only inventory: always on. */
  scan: true;
  /** safeOsUpdate may upgrade the OS packages. */
  osUpgrade: boolean;
  /**
   * The scan may run the read-only, cache-only OS update check as root (dnf: root's dnf
   * checks the cached repo signatures, which libdnf 4 cannot do for the login). Only when os
   * is on, the built-in collector scans the machine (no osUpdater), and the login already
   * has a sudo grant (an upgrade, a reboot or the docker helper): it never makes a host
   * that has no grant need sudo.
   */
  osCheck: boolean;
  /** reboot may reboot the host: every policy but scan-only, whatever `os` says. */
  reboot: boolean;
  /** The machine has a docker block (safeUpdate applies). */
  docker: boolean;
  /** What the host's own updater installs; null unless the policy is auto and os is on. */
  autoUpdates: OsAutoScope | null;
  /** pct may reach the machine as root in its container (a pct machine with the record). */
  pctExec: boolean;
}

function isOneOf<T extends string>(
  all: readonly T[],
  v: unknown,
): v is T {
  return typeof v === "string" && (all as readonly string[]).includes(v);
}

/**
 * The effective policy of one machine. Throws when the configuration is inconsistent:
 * an unknown policy, or an osAutoScope on a machine whose effective policy is not auto
 * (whether it set the policy itself or inherited it).
 */
export function effectivePolicy(
  m: PolicyMachine,
  g: PolicyGlobals,
): EffectivePolicy {
  const host = m.host ?? "(unnamed machine)";
  const inherited = m.osUpdatePolicy === undefined;
  const policy = m.osUpdatePolicy ?? g.osUpdatePolicy ?? "managed";
  if (!isOneOf(OS_UPDATE_POLICIES, policy)) {
    throw new Error(
      `${host}: unknown osUpdatePolicy "${
        String(policy)
      }" (expected managed, auto or scan-only)`,
    );
  }
  if (m.osAutoScope !== undefined && policy !== "auto") {
    throw new Error(
      `${host}: osAutoScope is set, but the effective osUpdatePolicy is ${policy}${
        inherited ? " (inherited from the fleet)" : ""
      }. osAutoScope applies only when the policy is auto: remove osAutoScope, or set osUpdatePolicy: auto`,
    );
  }
  if (policy !== "auto") return { policy, autoScope: null };
  const scope = m.osAutoScope ?? g.osAutoScope ?? "security";
  if (!isOneOf(OS_AUTO_SCOPES, scope)) {
    throw new Error(
      `${host}: unknown osAutoScope "${
        String(scope)
      }" (expected security or all)`,
    );
  }
  return { policy, autoScope: scope };
}

/** What @dmc/patch may do on one machine, derived from its effective policy. Throws like effectivePolicy. */
export function capabilitiesFor(
  m: PolicyMachine,
  g: PolicyGlobals,
): Capabilities {
  const { policy, autoScope } = effectivePolicy(m, g);
  const osOn = m.os !== false;
  const osUpgrade = osOn && policy === "managed";
  const reboot = policy !== "scan-only";
  const docker = m.docker !== undefined && m.docker !== null;
  return {
    scan: true,
    osUpgrade,
    // The collector runs the check; a machine with an osUpdater model never runs the collector.
    osCheck: osOn && m.osUpdater == null && (osUpgrade || reboot || docker),
    reboot,
    docker,
    autoUpdates: osOn && policy === "auto" ? autoScope : null,
    pctExec: m.reach === "pct" && unsafeRecord(m, "pctExec") !== null,
  };
}

/**
 * Why an OS action is refused for one machine, or null when it may run. The action is
 * `safeOsUpdate` (an OS upgrade) or `reboot`. Throws like effectivePolicy.
 */
export function osRefusal(
  action: "safeOsUpdate" | "reboot",
  m: PolicyMachine,
  g: PolicyGlobals,
): string | null {
  const caps = capabilitiesFor(m, g);
  const allowed = action === "safeOsUpdate" ? caps.osUpgrade : caps.reboot;
  if (allowed) return null;
  const host = m.host ?? "(unnamed machine)";
  if (action === "safeOsUpdate" && m.os === false) {
    return `${action} refused for ${host}: os is false, so OS upgrades are off for this machine`;
  }
  const { policy } = effectivePolicy(m, g);
  if (policy === "auto") {
    return `${action} refused for ${host}: osUpdatePolicy is auto (the host installs its own OS updates); use reboot for pending reboots`;
  }
  return action === "safeOsUpdate"
    ? `${action} refused for ${host}: osUpdatePolicy is scan-only (the host is only scanned, never upgraded or rebooted)`
    : `${action} refused for ${host}: osUpdatePolicy is scan-only (the host is only scanned; reboots are refused, even with force)`;
}

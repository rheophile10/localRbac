/* ============================================================================
 * compartments.ts — map compartmented RBAC onto per-resource MLS groups.
 *
 * The design decision that makes MLS a correct replacement for per-reader
 * keywraps: ONE MLS GROUP PER RESOURCE. A single shared group would collapse
 * compartments — every member holds the same epoch secret, so anyone could
 * derive any resource's DEK via the exporter. With one group per resource, only
 * that resource's granted members share its epoch secret, so only they can
 * derive its DEK. Non-members simply have no group state for it.
 *
 *   grant(resource, member)  = MLS add   → Welcome (to the member) + commit
 *   revoke(resource, leaf)   = MLS remove → commit; epoch advances, DEK rotates
 *   dek(resource)            = mlsExporter at the current epoch (per member)
 *
 * Coordinator (admin) holds every resource group and issues Welcomes/commits;
 * a member holds only the resource groups they were welcomed into. Handshake
 * ordering is the one thing MLS needs that a CRDT doesn't give for free — in
 * localRbac the consensus ceremony is where the coordinator sequences an
 * epoch's membership commits. This layer is transport-agnostic: it emits/*
 * consumes opaque byte blobs (Welcome, commit) that ride the existing changeset
 * channel.
 * ==========================================================================*/
import {
  foundGroup, addMember, removeMember, joinFromWelcome, applyCommit,
  resourceDek, epoch as mlsEpoch,
} from './mls';
import type { MlsSuite, MlsGroup, MlsIdentity } from './mls';
import type { KeyPackage } from 'ts-mls';

export interface GrantMaterial { resource: string; welcome: Uint8Array; commit: Uint8Array; }
export interface RevokeMaterial { resource: string; commit: Uint8Array; }

/** Coordinator (admin) view: founds and evolves one MLS group per resource. */
export const createCoordinatorCompartments = (self: MlsIdentity, suite: MlsSuite) => {
  const groups = new Map<string, MlsGroup>();
  const groupId = (resource: string): string => 'compartment:' + resource;

  const ensure = async (resource: string): Promise<MlsGroup> => {
    let g = groups.get(resource);
    if (!g) { g = await foundGroup(groupId(resource), self, suite); groups.set(resource, g); }
    return g;
  };

  /** Grant a member read/write of a resource = add them to its MLS group. */
  const grant = async (resource: string, memberPublicPackage: KeyPackage): Promise<GrantMaterial> => {
    const g = await ensure(resource);
    const r = await addMember(g, memberPublicPackage, suite);
    groups.set(resource, r.group);
    return { resource, welcome: r.welcome, commit: r.commit };
  };

  /** Revoke a member = remove their leaf; the epoch advances so the DEK rotates. */
  const revoke = async (resource: string, leafIndex: number): Promise<RevokeMaterial> => {
    const g = groups.get(resource);
    if (!g) throw new Error('no such compartment: ' + resource);
    const r = await removeMember(g, leafIndex, suite);
    groups.set(resource, r.group);
    return { resource, commit: r.commit };
  };

  const dek = async (resource: string): Promise<Uint8Array | null> => {
    const g = groups.get(resource);
    return g ? resourceDek(g, resource, suite) : null;
  };
  const epoch = (resource: string): bigint | null => {
    const g = groups.get(resource);
    return g ? mlsEpoch(g) : null;
  };
  const resources = (): string[] => [...groups.keys()];

  return { grant, revoke, dek, epoch, resources };
};

/** Member view: holds only the resource groups they were welcomed into. A
 *  resource they were never granted has NO group state — so its DEK is simply
 *  underivable (null), which is the compartment guarantee. */
export const createMemberCompartments = (self: MlsIdentity, suite: MlsSuite) => {
  const groups = new Map<string, MlsGroup>();

  const join = async (material: GrantMaterial): Promise<void> => {
    groups.set(material.resource, await joinFromWelcome(material.welcome, self, undefined, suite));
  };
  /** Apply a membership commit for a resource you already belong to (add/remove
   *  of some other member) to advance to the new epoch. */
  const apply = async (resource: string, commit: Uint8Array): Promise<void> => {
    const g = groups.get(resource);
    if (!g) throw new Error('not a member of compartment: ' + resource);
    groups.set(resource, await applyCommit(g, commit, suite));
  };
  /** The resource's DEK at the current epoch, or null if not a member. */
  const dek = async (resource: string): Promise<Uint8Array | null> => {
    const g = groups.get(resource);
    return g ? resourceDek(g, resource, suite) : null;
  };
  const has = (resource: string): boolean => groups.has(resource);
  const epoch = (resource: string): bigint | null => {
    const g = groups.get(resource);
    return g ? mlsEpoch(g) : null;
  };

  return { join, apply, dek, has, epoch };
};

export type CoordinatorCompartments = ReturnType<typeof createCoordinatorCompartments>;
export type MemberCompartments = ReturnType<typeof createMemberCompartments>;

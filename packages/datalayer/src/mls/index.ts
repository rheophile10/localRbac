/* MLS (RFC 9420) group key agreement + messaging for a subgroup.
 * Pure verbs over ts-mls; the ciphersuite + exporter label are protocol
 * constants. See mls.ts for the full rationale. */
export {
  MLS_SUITE, DEK_LABEL, mlsSuite, createIdentity, foundGroup,
  addMember, removeMember, joinFromWelcome, applyCommit, epoch, resourceDek,
  send, receive, encodeMessage, decodeMessage, encodeKeyPackage, decodeKeyPackage,
} from './mls';
export type {
  MlsSuite, MlsGroup, MlsIdentity, AddResult, RemoveResult, SendResult, ReceiveResult,
} from './mls';

// Compartmented RBAC over per-resource MLS groups (the keywrap replacement).
export { createCoordinatorCompartments, createMemberCompartments } from './compartments';
export type {
  CoordinatorCompartments, MemberCompartments, GrantMaterial, RevokeMaterial,
} from './compartments';

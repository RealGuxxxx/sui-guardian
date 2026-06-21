import type { ObjectSnapshot, ObservedBalanceChange, ObservedCall, ObservedObjectChange, ObservedTransaction, PackageVersionSnapshot } from './types.js';
import { canonicalizeSuiAddress, nowIso } from './utils.js';

interface GraphqlResponse<T> {
  data?: T;
  errors?: Array<{ message: string }>;
}

interface CheckpointListResponse {
  checkpoints: {
    nodes: Array<{
      sequenceNumber: number;
      timestamp: string;
    }>;
  };
}

export interface CheckpointHeader {
  sequenceNumber: number;
  timestamp: string;
}

interface LatestCheckpointResponse {
  checkpoint: {
    sequenceNumber: number;
  } | null;
}

interface CheckpointTransactionsResponse {
  checkpoint: {
    sequenceNumber: number;
    timestamp: string;
    transactions: {
      pageInfo: {
        hasNextPage: boolean;
        endCursor?: string | null;
      };
      nodes: Array<{
        digest: string;
        sender?: { address: string } | null;
        gasInput?: {
          gasPrice?: string | null;
          gasBudget?: string | null;
          gasSponsor?: { address: string } | null;
        } | null;
        transactionJson?: Record<string, unknown> | null;
        effects?: {
          status: 'SUCCESS' | 'FAILURE';
          executionError?: { message: string } | null;
          balanceChanges: {
            nodes: Array<{
              owner?: { address: string } | null;
              coinType: { repr: string };
              amount: string;
            }>;
          };
          objectChanges: {
            nodes: Array<{
              address: string;
              idCreated: boolean;
              idDeleted: boolean;
              inputState?: {
                version?: number | null;
                asMovePackage?: { address: string; version?: number | null } | null;
              } | null;
              outputState?: {
                version?: number | null;
                asMovePackage?: { address: string; version?: number | null } | null;
              } | null;
            }>;
          };
        } | null;
      }>;
    };
  } | null;
}

interface PackageVersionResponse {
  object: {
    asMovePackage: {
      address: string;
      version: number;
      previousTransaction?: {
        digest: string;
        sender?: { address: string } | null;
      } | null;
    } | null;
  } | null;
}

interface MoveObjectSnapshotResponse {
  object: {
    address: string;
    version?: number | null;
    digest?: string | null;
    asMoveObject?: {
      contents?: {
        json?: Record<string, unknown> | null;
        type?: {
          repr: string;
        } | null;
      } | null;
    } | null;
  } | null;
}

export class SuiGraphqlClient {
  constructor(private readonly endpoint: string) {}

  async getLatestCheckpoint(): Promise<number> {
    const response = await this.request<LatestCheckpointResponse>(`
      query LatestCheckpoint {
        checkpoint {
          sequenceNumber
        }
      }
    `);

    if (!response.checkpoint) {
      throw new Error('Unable to fetch latest checkpoint');
    }

    return response.checkpoint.sequenceNumber;
  }

  async getCheckpointsAfter(afterCheckpoint: number, limit: number): Promise<number[]> {
    const pageSize = clampGraphqlPageSize(limit);
    const response = await this.request<CheckpointListResponse>(`
      query CheckpointsAfter($afterCheckpoint: UInt53, $limit: Int!) {
        checkpoints(first: $limit, filter: { afterCheckpoint: $afterCheckpoint }) {
          nodes {
            sequenceNumber
            timestamp
          }
        }
      }
    `, {
      afterCheckpoint,
      limit: pageSize,
    });

    return response.checkpoints.nodes.map((item) => item.sequenceNumber);
  }

  async getCheckpointHeadersAfter(afterCheckpoint: number, limit: number): Promise<CheckpointHeader[]> {
    const pageSize = clampGraphqlPageSize(limit);
    const response = await this.request<CheckpointListResponse>(`
      query CheckpointsAfter($afterCheckpoint: UInt53, $limit: Int!) {
        checkpoints(first: $limit, filter: { afterCheckpoint: $afterCheckpoint }) {
          nodes {
            sequenceNumber
            timestamp
          }
        }
      }
    `, {
      afterCheckpoint,
      limit: pageSize,
    });

    return response.checkpoints.nodes.map((item) => ({
      sequenceNumber: item.sequenceNumber,
      timestamp: item.timestamp,
    }));
  }

  async getCheckpointTransactions(sequenceNumber: number, pageSize: number): Promise<ObservedTransaction[]> {
    const results: ObservedTransaction[] = [];
    let cursor: string | undefined;
    const transactionPageSize = clampGraphqlPageSize(pageSize);

    while (true) {
      const response = await this.request<CheckpointTransactionsResponse>(`
        query CheckpointTransactions($sequenceNumber: UInt53!, $cursor: String, $pageSize: Int!) {
          checkpoint(sequenceNumber: $sequenceNumber) {
            sequenceNumber
            timestamp
            transactions(first: $pageSize, after: $cursor) {
              pageInfo {
                hasNextPage
                endCursor
              }
              nodes {
                digest
                sender {
                  address
                }
                gasInput {
                  gasPrice
                  gasBudget
                  gasSponsor {
                    address
                  }
                }
                transactionJson
                effects {
                  status
                  executionError {
                    message
                  }
                  balanceChanges(first: 50) {
                    nodes {
                      owner {
                        address
                      }
                      coinType {
                        repr
                      }
                      amount
                    }
                  }
                  objectChanges(first: 50) {
                    nodes {
                      address
                      idCreated
                      idDeleted
                      inputState {
                        version
                        asMovePackage {
                          address
                          version
                        }
                      }
                      outputState {
                        version
                        asMovePackage {
                          address
                          version
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      `, {
        sequenceNumber,
        cursor,
        pageSize: transactionPageSize,
      });

      const checkpoint = response.checkpoint;
      if (!checkpoint) {
        break;
      }

      for (const node of checkpoint.transactions.nodes) {
        results.push({
          digest: node.digest,
          checkpoint: checkpoint.sequenceNumber,
          timestamp: checkpoint.timestamp,
          sender: node.sender?.address ? canonicalizeSuiAddress(node.sender.address) : undefined,
          gasSponsor: node.gasInput?.gasSponsor?.address
            ? canonicalizeSuiAddress(node.gasInput.gasSponsor.address)
            : undefined,
          gasPrice: node.gasInput?.gasPrice ?? undefined,
          gasBudget: node.gasInput?.gasBudget ?? undefined,
          status: node.effects?.status ?? 'SUCCESS',
          executionError: node.effects?.executionError?.message ?? undefined,
          calls: extractCalls(node.transactionJson),
          balanceChanges: mapBalanceChanges(node.effects?.balanceChanges?.nodes ?? []),
          objectChanges: mapObjectChanges(node.effects?.objectChanges?.nodes ?? []),
        });
      }

      if (!checkpoint.transactions.pageInfo.hasNextPage || !checkpoint.transactions.pageInfo.endCursor) {
        break;
      }

      cursor = checkpoint.transactions.pageInfo.endCursor;
    }

    return results;
  }

  async getPackageVersion(packageAddress: string): Promise<PackageVersionSnapshot | null> {
    const response = await this.request<PackageVersionResponse>(`
      query PackageVersion($address: SuiAddress!) {
        object(address: $address) {
          asMovePackage {
            address
            version
            previousTransaction {
              digest
              sender {
                address
              }
            }
          }
        }
      }
    `, {
      address: packageAddress,
    });

    const pkg = response.object?.asMovePackage;
    if (!pkg) {
      return null;
    }

    return {
      packageAddress: canonicalizeSuiAddress(pkg.address),
      version: pkg.version,
      digest: pkg.previousTransaction?.digest ?? undefined,
      sender: pkg.previousTransaction?.sender?.address
        ? canonicalizeSuiAddress(pkg.previousTransaction.sender.address)
        : undefined,
      updatedAt: nowIso(),
    };
  }

  async getMoveObjectSnapshot(
    projectId: string,
    projectName: string,
    label: string,
    address: string,
  ): Promise<ObjectSnapshot | null> {
    const response = await this.request<MoveObjectSnapshotResponse>(`
      query MoveObjectSnapshot($address: SuiAddress!) {
        object(address: $address) {
          address
          version
          digest
          asMoveObject {
            contents {
              json
              type {
                repr
              }
            }
          }
        }
      }
    `, {
      address,
    });

    const object = response.object;
    if (!object?.asMoveObject?.contents?.json) {
      return null;
    }

    return {
      label,
      address: canonicalizeSuiAddress(object.address),
      projectId,
      projectName,
      version: object.version ?? undefined,
      digest: object.digest ?? undefined,
      type: object.asMoveObject.contents.type?.repr ?? undefined,
      contents: object.asMoveObject.contents.json,
      updatedAt: nowIso(),
    };
  }

  private async request<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
    const response = await fetch(this.endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        query,
        variables,
      }),
    });

    if (!response.ok) {
      throw new Error(`GraphQL request failed: ${response.status} ${response.statusText}`);
    }

    const payload = (await response.json()) as GraphqlResponse<T>;
    if (payload.errors?.length) {
      throw new Error(payload.errors.map((item) => item.message).join('; '));
    }

    if (!payload.data) {
      throw new Error('GraphQL response missing data');
    }

    return payload.data;
  }
}

function clampGraphqlPageSize(value: number): number {
  if (!Number.isFinite(value)) {
    return 50;
  }
  return Math.min(50, Math.max(1, Math.floor(value)));
}

function mapBalanceChanges(nodes: Array<{ owner?: { address: string } | null; coinType: { repr: string }; amount: string }>): ObservedBalanceChange[] {
  return nodes.map((item) => ({
    owner: item.owner?.address ? canonicalizeSuiAddress(item.owner.address) : undefined,
    coinType: item.coinType.repr,
    amount: item.amount,
  }));
}

function mapObjectChanges(
  nodes: Array<{
    address: string;
    idCreated: boolean;
    idDeleted: boolean;
    inputState?: { version?: number | null; asMovePackage?: { address: string; version?: number | null } | null } | null;
    outputState?: { version?: number | null; asMovePackage?: { address: string; version?: number | null } | null } | null;
  }>,
): ObservedObjectChange[] {
  return nodes.map((item) => ({
    address: canonicalizeSuiAddress(item.address),
    idCreated: item.idCreated,
    idDeleted: item.idDeleted,
    inputVersion: item.inputState?.version ?? undefined,
    outputVersion: item.outputState?.version ?? undefined,
    isPackage: Boolean(item.inputState?.asMovePackage || item.outputState?.asMovePackage),
  }));
}

function extractCalls(transactionJson?: Record<string, unknown> | null): ObservedCall[] {
  const kind = transactionJson?.kind as Record<string, unknown> | undefined;
  const programmable = kind?.programmableTransaction as {
    inputs?: Array<Record<string, unknown>>;
    commands?: Array<Record<string, unknown>>;
  } | undefined;
  const commands = programmable?.commands ?? [];
  const inputs = programmable?.inputs ?? [];
  const calls: ObservedCall[] = [];

  for (const command of commands) {
    const moveCall = command.moveCall as Record<string, unknown> | undefined;
    if (!moveCall) {
      continue;
    }

    const pkg = moveCall.package;
    const module = moveCall.module;
    const fn = moveCall.function;

    if (typeof pkg === 'string' && typeof module === 'string' && typeof fn === 'string') {
      // Resolve pure argument values for this specific moveCall
      const args = (moveCall.arguments as Array<Record<string, unknown>> | undefined) ?? [];
      const pureInputs: Array<string | boolean> = [];

      for (const arg of args) {
        // Arguments that reference PTB inputs: {"Input": N}
        const inputIdx = arg['Input'];
        if (typeof inputIdx === 'number' && inputIdx < inputs.length) {
          const input = inputs[inputIdx];
          if (input?.['type'] === 'pure') {
            const val = input['value'];
            if (typeof val === 'string') {
              pureInputs.push(val);
            } else if (typeof val === 'boolean') {
              pureInputs.push(val);
            } else if (typeof val === 'number') {
              pureInputs.push(String(val));
            }
          }
        }
      }

      calls.push({
        package: canonicalizeSuiAddress(pkg),
        module,
        function: fn,
        ...(pureInputs.length > 0 ? { pureInputs } : {}),
      });
    }
  }

  return calls;
}
